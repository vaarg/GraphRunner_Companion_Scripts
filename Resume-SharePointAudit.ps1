<#
.SYNOPSIS
    SharePoint and OneDrive audit supplement for GraphRunner.
    Requires GraphRunner.ps1 to be dot-sourced first for Invoke-RefreshGraphTokens
    and Invoke-ForgeUserAgent.

.DESCRIPTION
    Three-phase workflow for auditing SharePoint and OneDrive.

    Phase 1 - Get-SPOSiteInventory:
        Admin-only. Uses Microsoft.Online.SharePoint.PowerShell to enumerate all
        site collections. Exports SharePointSiteInventory.csv. Requires SharePoint
        administrator access to the tenant.

    Phase 2 - Test-SharePointSiteAccess:
        Standard user. Tests Graph API access for each site in
        SharePointSiteInventory.csv. Exports AccessibleSharePointSites.csv and
        InaccessibleSharePointSites.csv. Handles token refresh the same way as
        Resume-GroupAudit.ps1.

    Phase 3 - Invoke-SearchSharePointByList:
        Searches across sites from AccessibleSharePointSites.csv using the Graph
        Search API with contentSources, bypassing the site enumeration step that
        fails in restricted environments. Compatible with the default_detectors.json
        detector-loop pattern.

.EXAMPLE
    . .\GraphRunner\GraphRunner.ps1
    . .\Resume-SharePointAudit.ps1

    # Phase 1 (admin): enumerate all site collections
    Get-SPOSiteInventory -AdminUrl 'https://contoso-admin.sharepoint.com'

    # Phase 2 (standard user): test which sites are accessible via Graph
    Test-SharePointSiteAccess -Tokens $tokens

    # Phase 3: search accessible sites
    Invoke-SearchSharePointByList -Tokens $tokens -SearchTerm 'password filetype:xlsx'

    # Detector-loop (same pattern as the GraphRunner wiki)
    $folderName = "SharePointSearch-" + (Get-Date -Format 'yyyyMMddHHmmss')
    New-Item -Path $folderName -ItemType Directory | Out-Null
    $spout = "$folderName\interesting-files.csv"
    $detectors = (Get-Content '.\default_detectors.json' | ConvertFrom-Json).Detectors
    foreach ($detect in $detectors) {
        Invoke-SearchSharePointByList -Tokens $tokens `
            -SearchTerm $detect.SearchQuery -DetectorName $detect.DetectorName `
            -PageResults -ResultCount 500 -ReportOnly -OutFile $spout -GraphRun
    }

.NOTES
    Encoding note: The file is pure ASCII. If you edit it, save as ASCII or
    UTF-8 with BOM. Windows PowerShell 5.1 reads files without a BOM as
    Windows-1252 by default, which silently corrupts multi-byte characters and
    causes parse errors.

    Phase 1 and Phase 2 are independent. Phase 1 requires SharePoint admin access;
    Phase 2 and Phase 3 work with standard user tokens. If Phase 1 is not available,
    supply SharePointSiteInventory.csv from another enumeration source with at least
    the columns: Title, Url, Template, Owner, Status, StorageUsageCurrent,
    LastContentModifiedDate, SiteCategory.
#>


function Get-SPOSiteInventory {
    <#
    .SYNOPSIS
        Phase 1. Enumerates all SharePoint site collections via the SharePoint Online
        PowerShell SDK and exports SharePointSiteInventory.csv. Requires SharePoint
        admin access. Installs the module automatically if not already present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminUrl,

        [string]$OutputFile = "SharePointSiteInventory.csv"
    )

    if (-not (Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ListAvailable)) {
        Write-Host -ForegroundColor Yellow "[*] Microsoft.Online.SharePoint.PowerShell not found -- installing for current user..."
        Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -ErrorAction Stop
    }
    Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop

    Write-Host -ForegroundColor Yellow "[*] Connecting to $AdminUrl (interactive sign-in)..."
    Connect-SPOService -Url $AdminUrl

    Write-Host -ForegroundColor Yellow "[*] Enumerating all site collections..."
    $sites = Get-SPOSite -Limit All

    $inventory = $sites | Select-Object `
        Title,
        Url,
        SiteId,
        Template,
        Owner,
        Status,
        StorageUsageCurrent,
        LastContentModifiedDate,
        @{ Name = 'SiteCategory'; Expression = {
            switch -Wildcard ($_.Template) {
                'TEAMCHANNEL*' { 'Teams channel site'; break }
                'GROUP*'       { 'Microsoft 365 group / Teams parent site'; break }
                'SPSPERS*'     { 'OneDrive'; break }
                default        { 'Other SharePoint site' }
            }
        }}

    $inventory | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host -ForegroundColor Green "[*] Exported $($sites.Count) site(s) to $OutputFile"
}


function Test-SharePointSiteAccess {
    <#
    .SYNOPSIS
        Phase 2. Tests Graph API access for each site in SharePointSiteInventory.csv.
        Exports AccessibleSharePointSites.csv and InaccessibleSharePointSites.csv.

    .DESCRIPTION
        Iterates every URL in the input CSV, issues a Graph GET /sites/{id} request,
        and classifies the result as accessible or inaccessible. Token handling mirrors
        Resume-GroupAudit.ps1: the ClientID is auto-detected from the JWT appid claim,
        proactive refreshes run on a configurable interval, and 401 responses trigger an
        immediate refresh-and-retry before giving up.

    .PARAMETER InputCsv
        Path to SharePointSiteInventory.csv (output of Get-SPOSiteInventory or
        equivalent). Must contain at minimum a Url column.

    .PARAMETER RefreshInterval
        Seconds between proactive token refreshes. Default: 300.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        [string]$InputCsv              = "SharePointSiteInventory.csv",
        [string]$AccessibleOutputCsv   = "AccessibleSharePointSites.csv",
        [string]$InaccessibleOutputCsv = "InaccessibleSharePointSites.csv",

        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge",
        [int]$RefreshInterval = 300
    )

    # Auto-detect ClientID from the appid claim in the JWT
    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        try {
            $payload = $Tokens.access_token.Split(".")[1]
            $payload = $payload.Replace('-', '+').Replace('_', '/')
            while ($payload.Length % 4) { $payload += "=" }
            $claims = [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
            if ($claims.appid) {
                $ClientID = $claims.appid
                Write-Host -ForegroundColor Yellow "[*] Auto-detected ClientID from token: $ClientID"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "[*] Could not auto-detect ClientID, using default ($ClientID)."
        }
    }

    if (-not (Test-Path $InputCsv)) {
        Write-Host -ForegroundColor Red "[!] Input CSV not found: $InputCsv"
        return
    }

    $inventory = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    if ($inventory.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No entries found in $InputCsv"
        return
    }

    Write-Host -ForegroundColor Yellow "[*] Testing Graph API access to $($inventory.Count) site(s)..."

    $accessToken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json"
    }

    $startTime       = Get-Date
    $refreshSpan     = [TimeSpan]::FromSeconds($RefreshInterval)
    $maxRetries      = 3
    $results         = [System.Collections.Generic.List[object]]::new()
    $checked         = 0
    $total           = $inventory.Count

    foreach ($entry in $inventory) {
        $checked++
        $sharePointUrl = $entry.Url

        if ([string]::IsNullOrWhiteSpace($sharePointUrl)) { continue }

        # Proactive token refresh
        if ((Get-Date) - $startTime -ge $refreshSpan) {
            Write-Host ""
            Write-Host -ForegroundColor Yellow "[*] Proactive token refresh ($checked/$total)..."
            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                -tenantid $tenantid -Resource $Resource -Client $Client `
                -ClientID $ClientID -Browser $Browser -Device $Device
            if ($global:tokens) {
                $accessToken  = $global:tokens.access_token
                $refreshToken = $global:tokens.refresh_token
                $headers["Authorization"] = "Bearer $accessToken"
                $startTime = Get-Date
            }
        }

        # Build Graph URI from the SharePoint URL
        $graphUri = $null
        try {
            $parsedUrl = [uri]$sharePointUrl
            $hostname  = $parsedUrl.Host
            $path      = $parsedUrl.AbsolutePath.TrimEnd("/")

            $graphUri = if ([string]::IsNullOrWhiteSpace($path)) {
                "https://graph.microsoft.com/v1.0/sites/$hostname"
            } else {
                "https://graph.microsoft.com/v1.0/sites/${hostname}:${path}"
            }
        } catch {
            Write-Host ""
            Write-Host -ForegroundColor Red "[!] Could not parse URL '$sharePointUrl': $($_.Exception.Message)"
            continue
        }

        $attempt  = 0
        $done     = $false
        $resultObj = $null

        while (-not $done -and $attempt -lt $maxRetries) {
            try {
                $site = Invoke-RestMethod -Method Get -Uri $graphUri `
                    -Headers $headers -ErrorAction Stop

                $siteCategory = switch -Wildcard ($entry.Template) {
                    "TEAMCHANNEL*" { "Teams channel site"; break }
                    "GROUP*"       { "Teams or Microsoft 365 group site"; break }
                    "SPSPERS*"     { "OneDrive"; break }
                    default        { "Other SharePoint site" }
                }

                $resultObj = [pscustomobject]@{
                    Accessible              = $true
                    Result                  = "Accessible"
                    InputTitle              = $entry.Title
                    InputUrl                = $sharePointUrl
                    SiteId                  = $site.id
                    DisplayName             = $site.displayName
                    Name                    = $site.name
                    WebUrl                  = $site.webUrl
                    CreatedDateTime         = $site.createdDateTime
                    Template                = $entry.Template
                    SiteCategory            = $siteCategory
                    Owner                   = $entry.Owner
                    Status                  = $entry.Status
                    StorageUsageCurrent     = $entry.StorageUsageCurrent
                    LastContentModifiedDate = $entry.LastContentModifiedDate
                    HttpStatus              = 200
                    Error                   = $null
                }
                $done = $true

            } catch {
                $statusCode = $null
                if ($null -ne $_.Exception.Response) {
                    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
                }

                $errorMessage = if ($_.ErrorDetails.Message) {
                    $_.ErrorDetails.Message
                } else {
                    $_.Exception.Message
                }

                if ($statusCode -eq 401) {
                    Write-Host ""
                    Write-Host -ForegroundColor Yellow "[!] 401 on '$($entry.Title)' -- refreshing token (attempt $($attempt + 1)/$maxRetries)..."
                    Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                        -tenantid $tenantid -Resource $Resource -Client $Client `
                        -ClientID $ClientID -Browser $Browser -Device $Device
                    if ($global:tokens) {
                        $accessToken  = $global:tokens.access_token
                        $refreshToken = $global:tokens.refresh_token
                        $headers["Authorization"] = "Bearer $accessToken"
                        $startTime = Get-Date
                    }
                    $attempt++
                } elseif ($statusCode -eq 429) {
                    $retryAfter = 10
                    try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                    Write-Host ""
                    Write-Host -ForegroundColor Red "[*] Rate limited (429) -- sleeping ${retryAfter}s..."
                    Start-Sleep -Seconds $retryAfter
                    # 429 does not count against the retry budget
                } else {
                    $result = switch ($statusCode) {
                        401     { "Authentication failed" }
                        403     { "Access denied" }
                        404     { "Not found or inaccessible" }
                        429     { "Throttled" }
                        default { "Request failed" }
                    }

                    $siteCategory = switch -Wildcard ($entry.Template) {
                        "TEAMCHANNEL*" { "Teams channel site"; break }
                        "GROUP*"       { "Teams or Microsoft 365 group site"; break }
                        "SPSPERS*"     { "OneDrive"; break }
                        default        { "Other SharePoint site" }
                    }

                    $resultObj = [pscustomobject]@{
                        Accessible              = $false
                        Result                  = $result
                        InputTitle              = $entry.Title
                        InputUrl                = $sharePointUrl
                        SiteId                  = $null
                        DisplayName             = $null
                        Name                    = $null
                        WebUrl                  = $null
                        CreatedDateTime         = $null
                        Template                = $entry.Template
                        SiteCategory            = $siteCategory
                        Owner                   = $entry.Owner
                        Status                  = $entry.Status
                        StorageUsageCurrent     = $entry.StorageUsageCurrent
                        LastContentModifiedDate = $entry.LastContentModifiedDate
                        HttpStatus              = $statusCode
                        Error                   = $errorMessage
                    }
                    $done = $true
                }
            }
        }

        if (-not $done) {
            Write-Host ""
            Write-Host -ForegroundColor Red "[!] Giving up on '$($entry.Title)' after $maxRetries attempts."
        }

        if ($resultObj) { $results.Add($resultObj) }

        $pct = [int](($checked / $total) * 100)
        Write-Host -NoNewline -ForegroundColor Cyan "`r[*] $checked/$total ($pct%) checked..."
        [System.Console]::Out.Flush()
    }

    Write-Host ""

    $accessibleSites   = @($results | Where-Object { $_.Accessible -eq $true }  | Sort-Object InputUrl -Unique)
    $inaccessibleSites = @($results | Where-Object { $_.Accessible -eq $false } | Sort-Object InputUrl -Unique)

    $accessibleSites   | Export-Csv -Path $AccessibleOutputCsv   -NoTypeInformation -Encoding UTF8
    $inaccessibleSites | Export-Csv -Path $InaccessibleOutputCsv -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Accessible sites:   $($accessibleSites.Count)"
    Write-Host "Other results:      $($inaccessibleSites.Count)"
    Write-Host "Accessible output:  $AccessibleOutputCsv"
    Write-Host "Other output:       $InaccessibleOutputCsv"
    Write-Host ""

    $accessibleSites | Select-Object DisplayName, WebUrl, SiteCategory, Template, SiteId | Format-Table -AutoSize
}


function Invoke-SearchSharePointByList {
    <#
    .SYNOPSIS
        Phase 3. Searches SharePoint and OneDrive for files matching a KQL query,
        scoped to the sites in AccessibleSharePointSites.csv. Bypasses the site
        enumeration step that fails in restricted environments.

    .DESCRIPTION
        Loads accessible sites from the input CSV, batches their web URLs into groups,
        and issues one Graph Search API request per batch with a KQL path: filter that
        restricts results to those sites. Results are aggregated and deduplicated across
        batches.

        Note: the Graph Search API's contentSources property only applies to external
        Microsoft Search Connectors, not native SharePoint/OneDrive content. Scoping
        is done via KQL path: in the queryString instead.

        Output format (CSV columns and interactive download behavior) is identical to
        GraphRunner's Invoke-SearchSharePointAndOneDrive so the function is a drop-in
        replacement in the detector-loop pattern from the GraphRunner wiki.

    .PARAMETER InputCsv
        Path to AccessibleSharePointSites.csv produced by Test-SharePointSiteAccess.
        Must contain a WebUrl column with the canonical site URL returned by Graph.

    .PARAMETER SearchTerm
        KQL query string. Accepts Graph Search API KQL syntax including filetype,
        content, and site operators.

    .PARAMETER ResultCount
        Number of results to request per page per batch. Default: 25.

    .PARAMETER PageResults
        If set, pages through all available results for each batch rather than
        stopping after the first page.

    .PARAMETER ReportOnly
        Suppress the interactive download prompt. Use this in the detector loop.

    .PARAMETER OutFile
        CSV file to append results to. Same columns as GraphRunner:
        Detector Name, File Name, Size, Location, DriveItemID, Preview, Last Modified Date.

    .PARAMETER GraphRun
        Suppress per-search status output except when hits are found. Use this in
        the detector loop.

    .PARAMETER RefreshInterval
        Seconds between proactive token refreshes. Default: 300.

    .EXAMPLE
        # Single search
        Invoke-SearchSharePointByList -Tokens $tokens -SearchTerm 'password filetype:xlsx'

    .EXAMPLE
        # Detector loop (mirrors the GraphRunner wiki pattern)
        $folderName = "SharePointSearch-" + (Get-Date -Format 'yyyyMMddHHmmss')
        New-Item -Path $folderName -ItemType Directory | Out-Null
        $spout = "$folderName\interesting-files.csv"
        $detectors = (Get-Content '.\default_detectors.json' | ConvertFrom-Json).Detectors
        foreach ($detect in $detectors) {
            Invoke-SearchSharePointByList -Tokens $tokens `
                -SearchTerm $detect.SearchQuery -DetectorName $detect.DetectorName `
                -PageResults -ResultCount 500 -ReportOnly -OutFile $spout -GraphRun
        }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        [Parameter(Mandatory = $true)]
        [string]$SearchTerm,

        [string]$InputCsv     = "AccessibleSharePointSites.csv",
        [int]$ResultCount     = 25,
        [string]$DetectorName = "Custom",
        [string]$OutFile      = "",
        [switch]$ReportOnly,
        [switch]$PageResults,
        [switch]$GraphRun,

        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device  = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge",

        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",
        [int]$RefreshInterval = 300
    )

    # Auto-detect ClientID from the appid claim in the JWT
    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        try {
            $payload = $Tokens.access_token.Split(".")[1]
            $payload = $payload.Replace('-', '+').Replace('_', '/')
            while ($payload.Length % 4) { $payload += "=" }
            $claims = [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
            if ($claims.appid) { $ClientID = $claims.appid }
        } catch {}
    }

    if (-not (Test-Path $InputCsv)) {
        Write-Host -ForegroundColor Red "[!] Input CSV not found: $InputCsv"
        Write-Host -ForegroundColor Red "[!] Run Test-SharePointSiteAccess first to generate the accessible sites list."
        return
    }

    $accessibleSites = @(Import-Csv -Path $InputCsv -ErrorAction Stop | Where-Object {
        $_.Accessible -eq "True" -and -not [string]::IsNullOrWhiteSpace($_.WebUrl)
    })

    if ($accessibleSites.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No accessible sites with a WebUrl found in $InputCsv"
        return
    }

    if (!$GraphRun) {
        Write-Host -ForegroundColor Yellow "[*] Searching $($accessibleSites.Count) site(s) for: $SearchTerm"
    }

    $userAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser

    $accessToken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "User-Agent"    = $userAgent
    }

    $graphApiUrl     = "https://graph.microsoft.com/v1.0/search/query"
    $startTime       = Get-Date
    $refreshSpan     = [TimeSpan]::FromSeconds($RefreshInterval)
    $maxRetries      = 3

    # Batch size for KQL path: scoping — kept at 15 to avoid very long query strings
    $batchSize = 15

    # Collect hits across all batches; keyed by DriveItemID to deduplicate
    $hitMap      = [System.Collections.Generic.Dictionary[string,bool]]::new()
    $resultArray = [System.Collections.Generic.List[object]]::new()
    $hitNumber   = 0

    $siteWebUrls  = @($accessibleSites | ForEach-Object { $_.WebUrl })
    $totalBatches = [Math]::Ceiling($siteWebUrls.Count / $batchSize)
    $got403       = $false

    for ($batchStart = 0; $batchStart -lt $siteWebUrls.Count; $batchStart += $batchSize) {
        $batchEnd     = [Math]::Min($batchStart + $batchSize, $siteWebUrls.Count) - 1
        $batchWebUrls = @($siteWebUrls[$batchStart..$batchEnd])
        $batchNum     = [int]($batchStart / $batchSize) + 1

        # Proactive token refresh
        if ((Get-Date) - $startTime -ge $refreshSpan) {
            if (!$GraphRun) { Write-Host "" }
            Write-Host -ForegroundColor Yellow "[*] Proactive token refresh (batch $batchNum/$totalBatches)..."
            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                -tenantid $tenantid -Resource $Resource -Client $Client `
                -ClientID $ClientID -Browser $Browser -Device $Device
            if ($global:tokens) {
                $accessToken  = $global:tokens.access_token
                $refreshToken = $global:tokens.refresh_token
                $headers["Authorization"] = "Bearer $accessToken"
                $startTime = Get-Date
            }
        }

        $from          = 0
        $continuePages = $true

        while ($continuePages) {
            $pathFilter  = ($batchWebUrls | ForEach-Object { "path:`"$_`"" }) -join " OR "
            $scopedQuery = "($SearchTerm) AND ($pathFilter)"

            $searchQuery = @{
                requests = @(@{
                    entityTypes = @("driveItem")
                    query       = @{ queryString = $scopedQuery }
                    from        = $from
                    size        = $ResultCount
                })
            }

            # Execute search with retry
            $attempt  = 0
            $done     = $false
            $response = $null

            while (-not $done -and $attempt -lt $maxRetries) {
                try {
                    $response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers `
                        -Method Post -Body ($searchQuery | ConvertTo-Json -Depth 10) `
                        -ErrorAction Stop
                    $done = $true
                } catch {
                    $statusCode = $null
                    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

                    if ($statusCode -eq 401) {
                        Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                            -tenantid $tenantid -Resource $Resource -Client $Client `
                            -ClientID $ClientID -Browser $Browser -Device $Device
                        if ($global:tokens) {
                            $accessToken  = $global:tokens.access_token
                            $refreshToken = $global:tokens.refresh_token
                            $headers["Authorization"] = "Bearer $accessToken"
                            $startTime = Get-Date
                        }
                        $attempt++
                    } elseif ($statusCode -eq 429) {
                        $retryAfter = 10
                        try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                        Start-Sleep -Seconds $retryAfter
                        # 429 does not count against the retry budget
                    } else {
                        if ($statusCode -eq 403) { $got403 = $true }
                        if (!$GraphRun) {
                            Write-Host -ForegroundColor Red "`n[!] Search failed for batch $batchNum/$totalBatches (HTTP $statusCode): $($_.Exception.Message)"
                        }
                        $done = $true
                    }
                }
            }

            if ($null -eq $response) {
                $continuePages = $false
                break
            }

            $hitsContainer = $response.value[0].hitsContainers[0]
            if ($null -eq $hitsContainer -or $null -eq $hitsContainer.hits) {
                $continuePages = $false
                break
            }

            $batchResultsList = [System.Collections.Generic.List[object]]::new()

            foreach ($hit in $hitsContainer.hits) {
                $filename         = $hit.resource.name
                $createdDate      = $hit.resource.fileSystemInfo.createdDateTime
                $lastModifiedDate = $hit.resource.lastModifiedDateTime
                $sizeInBytes      = [long]$hit.resource.size
                $sizeFormatted    = if ($sizeInBytes -lt 1024) {
                    "{0:N0} Bytes" -f $sizeInBytes
                } elseif ($sizeInBytes -lt 1048576) {
                    "{0:N2} KB"    -f ($sizeInBytes / 1024)
                } elseif ($sizeInBytes -lt 1073741824) {
                    "{0:N2} MB"    -f ($sizeInBytes / 1048576)
                } else {
                    "{0:N2} GB"    -f ($sizeInBytes / 1073741824)
                }
                $summary     = $hit.summary
                $location    = $hit.resource.webUrl
                $driveId     = $hit.resource.parentReference.driveId
                $itemId      = $hit.resource.id
                $driveItemId = "${driveId}:${itemId}"

                # Deduplicate across batches
                if ($hitMap.ContainsKey($driveItemId)) { continue }
                $hitMap[$driveItemId] = $true

                $resultInfo = [pscustomobject]@{
                    result       = $hitNumber
                    filename     = $filename
                    driveitemids = $driveItemId
                }
                $logInfo = [pscustomobject]@{
                    "Detector Name"      = $DetectorName
                    "File Name"          = $filename
                    "Size"               = $sizeFormatted
                    "Location"           = $location
                    "DriveItemID"        = $driveItemId
                    "Preview"            = $summary
                    "Last Modified Date" = $lastModifiedDate
                }

                $resultArray.Add($resultInfo)
                $batchResultsList.Add($logInfo)

                if (!$ReportOnly) {
                    Write-Host "Result [$hitNumber]"
                    Write-Host "File Name: $filename"
                    Write-Host "Location: $location"
                    Write-Host "Created Date: $createdDate"
                    Write-Host "Last Modified Date: $lastModifiedDate"
                    Write-Host "Size: $sizeFormatted"
                    Write-Host "File Preview: $summary"
                    Write-Host "DriveID & Item ID: $driveId\:$itemId"
                    Write-Host ("=" * 80)
                }

                $hitNumber++
            }

            if ($OutFile -and $batchResultsList.Count -gt 0) {
                if (!$GraphRun) {
                    Write-Host -ForegroundColor Yellow "`n[*] Writing $($batchResultsList.Count) result(s) from batch $batchNum/$totalBatches to $OutFile"
                }
                $batchResultsList | Export-Csv -Path $OutFile -NoTypeInformation -Append
            }

            $from += $ResultCount
            $continuePages = $PageResults -and [bool]$hitsContainer.moreResultsAvailable
        }

        if (!$GraphRun) {
            $pct = [int](($batchNum / $totalBatches) * 100)
            Write-Host -NoNewline -ForegroundColor Cyan "`r[*] Batch $batchNum/$totalBatches ($pct%) -- $hitNumber hit(s) so far..."
            [System.Console]::Out.Flush()
        }
    }

    if (!$GraphRun) { Write-Host "" }

    $totalHits = $hitNumber

    if ($got403) {
        Write-Host ""
        Write-Host -ForegroundColor Yellow "[!] One or more batches returned HTTP 403 -- the Search API may be restricted in this tenant."
        Write-Host -ForegroundColor Yellow "[*] Try the drive-level fallback instead:"
        Write-Host -ForegroundColor Cyan "      1. Get-SharePointDrives -Tokens `$tokens -InputCsv '$InputCsv'"
        Write-Host -ForegroundColor Cyan "      2. Invoke-DriveSearchSharePointByList -Tokens `$tokens -InputCsv '.\AccessibleSharePointDrives.csv' -SearchTerm '$SearchTerm'"
    }

    if (!$GraphRun) {
        Write-Host -ForegroundColor Yellow "[*] Found $totalHits unique match(es) for: $SearchTerm"
    } elseif ($totalHits -gt 0) {
        Write-Host -ForegroundColor Yellow "[*] Found $totalHits match(es) for detector: $DetectorName"
    }

    if (!$ReportOnly -and $totalHits -gt 0) {
        $promptMessage = "[*] Do you want to download any of these files? (Yes/No/All)"
        $downloading   = $true

        while ($downloading) {
            Write-Host -ForegroundColor Cyan $promptMessage
            $answer = (Read-Host).ToLower()

            if ($answer -eq "yes" -or $answer -eq "y") {
                Write-Host -ForegroundColor Cyan '[*] Enter the result number(s) to download. Ex. "0,10,24"'
                $resultToDownload = Read-Host
                foreach ($res in ($resultToDownload -split ",")) {
                    $idx = $res.Trim()
                    if ($idx -match '^\d+$') {
                        $fileInfo = $resultArray | Where-Object { $_.result -eq [int]$idx }
                        if ($fileInfo) {
                            Invoke-DriveFileDownload -Tokens $Tokens `
                                -DriveItemIDs $fileInfo.driveitemids `
                                -FileName     $fileInfo.filename `
                                -Device       $Device `
                                -Browser      $Browser
                        }
                    }
                }
                $promptMessage = "[*] Do you want to download any more files? (Yes/No/All)"
            } elseif ($answer -eq "no" -or $answer -eq "n") {
                Write-Output "[*] Quitting..."
                $downloading = $false
            } elseif ($answer -eq "all") {
                Write-Host -ForegroundColor Cyan "[***] WARNING - Downloading ALL $totalHits match(es)."
                foreach ($fileInfo in $resultArray) {
                    Invoke-DriveFileDownload -Tokens $Tokens `
                        -DriveItemIDs $fileInfo.driveitemids `
                        -FileName     $fileInfo.filename `
                        -Device       $Device `
                        -Browser      $Browser
                }
                $downloading = $false
            } else {
                Write-Output "Invalid input. Please enter Yes, No, or All."
            }
        }
    }
}


function Get-SharePointDrives {
    <#
    .SYNOPSIS
        Fallback pre-step. Enumerates document library drives for each accessible site
        and exports AccessibleSharePointDrives.csv for use with
        Invoke-DriveSearchSharePointByList. Run this once; the drives CSV is then reused
        across all fallback searches without re-enumerating.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        [string]$InputCsv   = "AccessibleSharePointSites.csv",
        [string]$OutputFile = "AccessibleSharePointDrives.csv",

        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge",
        [int]$RefreshInterval = 300
    )

    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        try {
            $payload = $Tokens.access_token.Split(".")[1]
            $payload = $payload.Replace('-', '+').Replace('_', '/')
            while ($payload.Length % 4) { $payload += "=" }
            $claims = [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
            if ($claims.appid) {
                $ClientID = $claims.appid
                Write-Host -ForegroundColor Yellow "[*] Auto-detected ClientID from token: $ClientID"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "[*] Could not auto-detect ClientID, using default ($ClientID)."
        }
    }

    if (-not (Test-Path $InputCsv)) {
        Write-Host -ForegroundColor Red "[!] Input CSV not found: $InputCsv"
        return
    }

    $accessibleSites = @(Import-Csv -Path $InputCsv -ErrorAction Stop | Where-Object {
        $_.Accessible -eq "True" -and -not [string]::IsNullOrWhiteSpace($_.SiteId)
    })

    if ($accessibleSites.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No accessible sites found in $InputCsv"
        return
    }

    Write-Host -ForegroundColor Yellow "[*] Enumerating drives for $($accessibleSites.Count) site(s)..."

    $accessToken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json"
    }

    $startTime   = Get-Date
    $refreshSpan = [TimeSpan]::FromSeconds($RefreshInterval)
    $maxRetries  = 3
    $drives      = [System.Collections.Generic.List[object]]::new()
    $checked     = 0
    $total       = $accessibleSites.Count

    foreach ($site in $accessibleSites) {
        $checked++

        if ((Get-Date) - $startTime -ge $refreshSpan) {
            Write-Host ""
            Write-Host -ForegroundColor Yellow "[*] Proactive token refresh ($checked/$total)..."
            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                -tenantid $tenantid -Resource $Resource -Client $Client `
                -ClientID $ClientID -Browser $Browser -Device $Device
            if ($global:tokens) {
                $accessToken  = $global:tokens.access_token
                $refreshToken = $global:tokens.refresh_token
                $headers["Authorization"] = "Bearer $accessToken"
                $startTime = Get-Date
            }
        }

        $attempt = 0
        $done    = $false

        while (-not $done -and $attempt -lt $maxRetries) {
            try {
                $response = Invoke-RestMethod `
                    -Method Get `
                    -Uri "https://graph.microsoft.com/v1.0/sites/$($site.SiteId)/drives" `
                    -Headers $headers `
                    -ErrorAction Stop

                foreach ($drive in $response.value) {
                    $drives.Add([pscustomobject]@{
                        SiteId      = $site.SiteId
                        SiteWebUrl  = $site.WebUrl
                        DriveId     = $drive.id
                        DriveName   = $drive.name
                        DriveType   = $drive.driveType
                        DriveWebUrl = $drive.webUrl
                    })
                }
                $done = $true

            } catch {
                $statusCode = $null
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

                if ($statusCode -eq 401) {
                    Write-Host ""
                    Write-Host -ForegroundColor Yellow "[!] 401 on '$($site.WebUrl)' -- refreshing token (attempt $($attempt + 1)/$maxRetries)..."
                    Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                        -tenantid $tenantid -Resource $Resource -Client $Client `
                        -ClientID $ClientID -Browser $Browser -Device $Device
                    if ($global:tokens) {
                        $accessToken  = $global:tokens.access_token
                        $refreshToken = $global:tokens.refresh_token
                        $headers["Authorization"] = "Bearer $accessToken"
                        $startTime = Get-Date
                    }
                    $attempt++
                } elseif ($statusCode -eq 429) {
                    $retryAfter = 10
                    try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                    Write-Host ""
                    Write-Host -ForegroundColor Red "[*] Rate limited (429) -- sleeping ${retryAfter}s..."
                    Start-Sleep -Seconds $retryAfter
                } else {
                    Write-Host ""
                    Write-Host -ForegroundColor Red "[!] HTTP $statusCode enumerating drives for '$($site.WebUrl)': $($_.Exception.Message)"
                    $done = $true
                }
            }
        }

        $pct = [int](($checked / $total) * 100)
        Write-Host -NoNewline -ForegroundColor Cyan "`r[*] $checked/$total ($pct%) -- $($drives.Count) drive(s) found so far..."
        [System.Console]::Out.Flush()
    }

    Write-Host ""

    if ($drives.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No drives enumerated."
        return
    }

    $drives | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host -ForegroundColor Green "[*] Exported $($drives.Count) drive(s) across $total site(s) to $OutputFile"
}


function Invoke-DriveSearchSharePointByList {
    <#
    .SYNOPSIS
        Fallback search. Uses the per-drive search endpoint instead of the Search API,
        for tenants where POST /search/query returns HTTP 403.

    .DESCRIPTION
        Reads drive IDs from AccessibleSharePointDrives.csv (produced by
        Get-SharePointDrives) and issues GET /drives/{id}/root/search(q='...') for each
        drive. Because this endpoint does not support KQL managed properties, the
        SearchTerm is parsed before sending: filetype: and filename: tokens are stripped
        and re-applied as a client-side post-filter on the returned item names; NEAR()
        operators are removed; the remaining keywords are passed as q=.

        Output CSV format is identical to Invoke-SearchSharePointByList (same column
        names). The Preview column is always empty as the drive search endpoint does not
        return content snippets.

    .PARAMETER InputCsv
        Path to AccessibleSharePointDrives.csv produced by Get-SharePointDrives.

    .PARAMETER SearchTerm
        KQL query string as used with Invoke-SearchSharePointByList. filetype: and
        filename: filters are extracted and applied client-side. NEAR() operators are
        stripped. Other KQL operators are passed through as plain keywords.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        [Parameter(Mandatory = $true)]
        [string]$SearchTerm,

        [string]$InputCsv     = "AccessibleSharePointDrives.csv",
        [int]$ResultCount     = 25,
        [string]$DetectorName = "Custom",
        [string]$OutFile      = "",
        [switch]$ReportOnly,
        [switch]$PageResults,
        [switch]$GraphRun,

        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device  = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge",

        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",
        [int]$RefreshInterval = 300
    )

    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        try {
            $payload = $Tokens.access_token.Split(".")[1]
            $payload = $payload.Replace('-', '+').Replace('_', '/')
            while ($payload.Length % 4) { $payload += "=" }
            $claims = [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
            if ($claims.appid) { $ClientID = $claims.appid }
        } catch {}
    }

    if (-not (Test-Path $InputCsv)) {
        Write-Host -ForegroundColor Red "[!] Input CSV not found: $InputCsv"
        Write-Host -ForegroundColor Red "[!] Run Get-SharePointDrives first to generate the drives list."
        return
    }

    $drives = @(Import-Csv -Path $InputCsv -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.DriveId)
    })

    if ($drives.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No drives found in $InputCsv"
        return
    }

    # Parse SearchTerm: extract file filters and build a clean q= keyword for the drive API.
    # filetype: and filename: tokens are stripped and re-applied as client-side post-filters.
    # NEAR() operators are removed. Remaining text is passed as q=.

    $extensions = @(
        [regex]::Matches($SearchTerm, '(?i)filetype:([.\w-]+)') |
            ForEach-Object { $_.Groups[1].Value }
    )

    $filenamePatterns = @(
        [regex]::Matches($SearchTerm, '(?i)filename:"([^"]+)"|(?i)filename:(\S+)') |
            ForEach-Object {
                if ($_.Groups[1].Success -and $_.Groups[1].Value) { $_.Groups[1].Value }
                else { $_.Groups[2].Value }
            } |
            Where-Object { $_ }
    )

    $cleanedQuery = $SearchTerm
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)filetype:[.\w-]+', '')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)filename:"[^"]+"', '')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)filename:\S+', '')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '\bNEAR\(n=\d+\)\s*', ' ')
    # Strip KQL trailing wildcards -- the drive search endpoint returns 400 on wildcard terms
    $cleanedQuery = $cleanedQuery -replace '(\w)\*', '$1'
    # Remove parenthesised groups that contain only operators/whitespace after stripping
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)\(\s*(?:(?:AND|OR)\s*)+\)', '')
    # Remove orphaned operators immediately after ( or immediately before )
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)\(\s*(?:AND|OR)\s+', '(')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)\s+(?:AND|OR)\s*\)', ')')
    # Collapse consecutive operators left by the above passes
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)\b(AND|OR)\b(?:\s+\b(?:AND|OR)\b)+', '$1')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '\(\s*\)', '')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)^\s*\b(AND|OR)\b\s*', '')
    $cleanedQuery = [regex]::Replace($cleanedQuery, '(?i)\s*\b(AND|OR)\b\s*$', '')
    $cleanedQuery = $cleanedQuery.Trim() -replace '\s{2,}', ' '

    # If nothing remains after stripping, derive a keyword from the extracted identifiers
    if ([string]::IsNullOrWhiteSpace($cleanedQuery)) {
        if ($filenamePatterns.Count -gt 0) {
            $cleanedQuery = ($filenamePatterns) -join ' '
        } elseif ($extensions.Count -gt 0) {
            $cleanedQuery = ($extensions |
                ForEach-Object { $_ -replace '^\.', '' } |
                Where-Object { $_ }) -join ' '
        }
    }

    if ([string]::IsNullOrWhiteSpace($cleanedQuery)) {
        Write-Host -ForegroundColor Red "[!] Could not derive a usable search term from: $SearchTerm"
        return
    }

    if (!$GraphRun) {
        Write-Host -ForegroundColor Yellow "[*] Searching $($drives.Count) drive(s) for: $SearchTerm"
        Write-Host -ForegroundColor Yellow "[*] Drive API query: $cleanedQuery"
        if ($extensions.Count -gt 0) {
            Write-Host -ForegroundColor Yellow "[*] Client-side extension filter: $($extensions -join ', ')"
        }
        if ($filenamePatterns.Count -gt 0) {
            Write-Host -ForegroundColor Yellow "[*] Client-side filename filter: $($filenamePatterns -join ', ')"
        }
    }

    $userAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser

    $accessToken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "User-Agent"    = $userAgent
    }

    $startTime   = Get-Date
    $refreshSpan = [TimeSpan]::FromSeconds($RefreshInterval)
    $maxRetries  = 3
    $selectFields = "id,name,size,webUrl,parentReference,fileSystemInfo,file,lastModifiedDateTime"

    $hitMap      = [System.Collections.Generic.Dictionary[string,bool]]::new()
    $resultArray = [System.Collections.Generic.List[object]]::new()
    $hitNumber   = 0
    $driveNum    = 0

    foreach ($drive in $drives) {
        $driveNum++

        if ((Get-Date) - $startTime -ge $refreshSpan) {
            if (!$GraphRun) {
                Write-Host -ForegroundColor Yellow "`n[*] Proactive token refresh (drive $driveNum/$($drives.Count))..."
            }
            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                -tenantid $tenantid -Resource $Resource -Client $Client `
                -ClientID $ClientID -Browser $Browser -Device $Device
            if ($global:tokens) {
                $accessToken  = $global:tokens.access_token
                $refreshToken = $global:tokens.refresh_token
                $headers["Authorization"] = "Bearer $accessToken"
                $startTime = Get-Date
            }
        }

        $safeQuery     = $cleanedQuery -replace "'", "''"
        $currentUri    = "https://graph.microsoft.com/v1.0/drives/$($drive.DriveId)/root/search(q='$safeQuery')?`$top=$ResultCount&`$select=$selectFields"
        $continuePages = $true
        $batchResultsList = [System.Collections.Generic.List[object]]::new()

        while ($continuePages) {
            $attempt  = 0
            $done     = $false
            $response = $null

            while (-not $done -and $attempt -lt $maxRetries) {
                try {
                    $response = Invoke-RestMethod -Uri $currentUri -Headers $headers `
                        -Method Get -ErrorAction Stop
                    $done = $true
                } catch {
                    $statusCode = $null
                    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

                    if ($statusCode -eq 401) {
                        Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                            -tenantid $tenantid -Resource $Resource -Client $Client `
                            -ClientID $ClientID -Browser $Browser -Device $Device
                        if ($global:tokens) {
                            $accessToken  = $global:tokens.access_token
                            $refreshToken = $global:tokens.refresh_token
                            $headers["Authorization"] = "Bearer $accessToken"
                            $startTime = Get-Date
                        }
                        $attempt++
                    } elseif ($statusCode -eq 429) {
                        $retryAfter = 10
                        try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                        Start-Sleep -Seconds $retryAfter
                    } else {
                        if (!$GraphRun) {
                            Write-Host -ForegroundColor Red "`n[!] Search failed for drive '$($drive.DriveName)' in '$($drive.SiteWebUrl)' (HTTP $statusCode): $($_.Exception.Message)"
                        }
                        $done = $true
                    }
                }
            }

            if ($null -eq $response -or $null -eq $response.value) {
                $continuePages = $false
                break
            }

            foreach ($item in $response.value) {
                # Client-side post-filter: check extension and filename patterns
                $matchesFilter = $false

                if ($extensions.Count -eq 0 -and $filenamePatterns.Count -eq 0) {
                    $matchesFilter = $true
                } else {
                    foreach ($fn in $filenamePatterns) {
                        if ($item.name -like $fn) { $matchesFilter = $true; break }
                    }
                    if (-not $matchesFilter -and $extensions.Count -gt 0) {
                        $itemExt = [System.IO.Path]::GetExtension($item.name).TrimStart('.')
                        foreach ($ext in $extensions) {
                            if ($ext -match '^\..') {
                                # Extension starts with a dot (e.g. .git-credentials) — match full filename
                                if ($item.name -ieq $ext) { $matchesFilter = $true; break }
                            } elseif ($itemExt -ieq $ext) {
                                $matchesFilter = $true; break
                            }
                        }
                    }
                }

                if (-not $matchesFilter) { continue }

                $driveId     = $item.parentReference.driveId
                $itemId      = $item.id
                $driveItemId = "${driveId}:${itemId}"

                if ($hitMap.ContainsKey($driveItemId)) { continue }
                $hitMap[$driveItemId] = $true

                $sizeInBytes   = [long]$item.size
                $sizeFormatted = if ($sizeInBytes -lt 1024) {
                    "{0:N0} Bytes" -f $sizeInBytes
                } elseif ($sizeInBytes -lt 1048576) {
                    "{0:N2} KB"    -f ($sizeInBytes / 1024)
                } elseif ($sizeInBytes -lt 1073741824) {
                    "{0:N2} MB"    -f ($sizeInBytes / 1048576)
                } else {
                    "{0:N2} GB"    -f ($sizeInBytes / 1073741824)
                }

                $createdDate      = $item.fileSystemInfo.createdDateTime
                $lastModifiedDate = $item.lastModifiedDateTime

                $resultInfo = [pscustomobject]@{
                    result       = $hitNumber
                    filename     = $item.name
                    driveitemids = $driveItemId
                }
                $logInfo = [pscustomobject]@{
                    "Detector Name"      = $DetectorName
                    "File Name"          = $item.name
                    "Size"               = $sizeFormatted
                    "Location"           = $item.webUrl
                    "DriveItemID"        = $driveItemId
                    "Preview"            = $null
                    "Last Modified Date" = $lastModifiedDate
                }

                $resultArray.Add($resultInfo)
                $batchResultsList.Add($logInfo)

                if (!$ReportOnly) {
                    Write-Host "Result [$hitNumber]"
                    Write-Host "File Name: $($item.name)"
                    Write-Host "Location: $($item.webUrl)"
                    Write-Host "Created Date: $createdDate"
                    Write-Host "Last Modified Date: $lastModifiedDate"
                    Write-Host "Size: $sizeFormatted"
                    Write-Host "DriveID & Item ID: $driveId\:$itemId"
                    Write-Host ("=" * 80)
                }

                $hitNumber++
            }

            $continuePages = $PageResults -and -not [string]::IsNullOrWhiteSpace($response.'@odata.nextLink')
            if ($continuePages) { $currentUri = $response.'@odata.nextLink' }
        }

        if ($OutFile -and $batchResultsList.Count -gt 0) {
            if (!$GraphRun) {
                Write-Host -ForegroundColor Yellow "`n[*] Writing $($batchResultsList.Count) result(s) from '$($drive.DriveName)' ($($drive.SiteWebUrl)) to $OutFile"
            }
            $batchResultsList | Export-Csv -Path $OutFile -NoTypeInformation -Append
        }

        if (!$GraphRun) {
            $pct = [int](($driveNum / $drives.Count) * 100)
            Write-Host -NoNewline -ForegroundColor Cyan "`r[*] Drive $driveNum/$($drives.Count) ($pct%) -- $($drive.DriveName) -- $hitNumber hit(s) so far..."
            [System.Console]::Out.Flush()
        }
    }

    if (!$GraphRun) { Write-Host "" }

    $totalHits = $hitNumber

    if (!$GraphRun) {
        Write-Host -ForegroundColor Yellow "[*] Found $totalHits unique match(es) for: $SearchTerm"
    } elseif ($totalHits -gt 0) {
        Write-Host -ForegroundColor Yellow "[*] Found $totalHits match(es) for detector: $DetectorName"
    }

    if (!$ReportOnly -and $totalHits -gt 0) {
        $promptMessage = "[*] Do you want to download any of these files? (Yes/No/All)"
        $downloading   = $true

        while ($downloading) {
            Write-Host -ForegroundColor Cyan $promptMessage
            $answer = (Read-Host).ToLower()

            if ($answer -eq "yes" -or $answer -eq "y") {
                Write-Host -ForegroundColor Cyan '[*] Enter the result number(s) to download. Ex. "0,10,24"'
                $resultToDownload = Read-Host
                foreach ($res in ($resultToDownload -split ",")) {
                    $idx = $res.Trim()
                    if ($idx -match '^\d+$') {
                        $fileInfo = $resultArray | Where-Object { $_.result -eq [int]$idx }
                        if ($fileInfo) {
                            Invoke-DriveFileDownload -Tokens $Tokens `
                                -DriveItemIDs $fileInfo.driveitemids `
                                -FileName     $fileInfo.filename `
                                -Device       $Device `
                                -Browser      $Browser
                        }
                    }
                }
                $promptMessage = "[*] Do you want to download any more files? (Yes/No/All)"
            } elseif ($answer -eq "no" -or $answer -eq "n") {
                Write-Output "[*] Quitting..."
                $downloading = $false
            } elseif ($answer -eq "all") {
                Write-Host -ForegroundColor Cyan "[***] WARNING - Downloading ALL $totalHits match(es)."
                foreach ($fileInfo in $resultArray) {
                    Invoke-DriveFileDownload -Tokens $Tokens `
                        -DriveItemIDs $fileInfo.driveitemids `
                        -FileName     $fileInfo.filename `
                        -Device       $Device `
                        -Browser      $Browser
                }
                $downloading = $false
            } else {
                Write-Output "Invalid input. Please enter Yes, No, or All."
            }
        }
    }
}
