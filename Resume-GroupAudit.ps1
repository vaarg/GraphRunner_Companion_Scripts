<#
    .SYNOPSIS
        Two-phase replacement for Get-UpdatableGroups that supports resuming.
        Requires GraphRunner.ps1 to be dot-sourced first for Invoke-RefreshGraphTokens.

    .DESCRIPTION
        Phase 1 - Get-GraphGroups: Enumerate all groups to CSV without any permission
        checks. Fast; use this to build the full group list before checking access.

        Phase 2 - Test-GraphGroupMemberAccess: Run estimateAccess on a specific list
        of group IDs. Accepts arrays, CSV (from phase 1), or text files. Handles 401
        token expiry reactively (immediate refresh + retry) rather than only on a timer.
        Use -Skip or -StartFromId to resume a partial run.

    .EXAMPLE
        # Dot-source both files
        . .\GraphRunner\GraphRunner.ps1
        . .\Resume-GroupAudit.ps1

        # Phase 1: Build the full group list (fast, no permission checks)
        Get-GraphGroups -Tokens $tokens -OutputFile .\all_groups.csv

        # Phase 2: Check all groups
        Test-GraphGroupMemberAccess -Tokens $tokens -InputCsv .\all_groups.csv -OutputFile .\updatable.csv

        # Resume after failure at index ~200
        Test-GraphGroupMemberAccess -Tokens $tokens -InputCsv .\all_groups.csv -Skip 200 -OutputFile .\updatable_resume.csv

        # Resume from a specific known group ID
        Test-GraphGroupMemberAccess -Tokens $tokens -InputCsv .\all_groups.csv -StartFromId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutputFile .\updatable_resume.csv

        # Check a specific ad-hoc set of groups
        Test-GraphGroupMemberAccess -Tokens $tokens -GroupIds @("guid1","guid2") -OutputFile .\updatable_specific.csv
#>


function Get-GraphGroups {
    <#
    .SYNOPSIS
        Enumerates all Entra ID groups and exports id/displayName/description/mail to CSV.
        This is phase 1 of the two-phase audit workflow. It does NOT check permissions.
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        [string]$GraphApiEndpoint = "https://graph.microsoft.com/v1.0/groups",

        [Parameter(Mandatory = $False)]
        [string]$OutputFile = "all_groups.csv",

        [Parameter(Mandatory = $False)]
        [string[]]$Keyword
    )

    $accesstoken = $Tokens.access_token
    $headers = @{
        "Authorization" = "Bearer $accesstoken"
        "Content-Type"  = "application/json"
    }

    $allGroups = @()
    $page = 0

    Write-Host -ForegroundColor Yellow "[*] Enumerating groups (no permission checks)..."

    do {
        try {
            $response = Invoke-RestMethod -Uri $GraphApiEndpoint -Headers $headers -Method Get
            $page++

            foreach ($group in $response.value) {
                if ($Keyword) {
                    $match = $false
                    foreach ($kw in $Keyword) {
                        if (($group.displayName -and $group.displayName -like "*$kw*") -or
                            ($group.description -and $group.description -like "*$kw*")) {
                            $match = $true
                            break
                        }
                    }
                    if (-not $match) { continue }
                }

                $allGroups += [PSCustomObject]@{
                    id          = $group.id
                    displayName = $group.displayName
                    description = $group.description
                    mail        = $group.mail
                }
            }

            Write-Host -ForegroundColor Yellow "[*] Page $page - $($allGroups.Count) groups so far..."
            $GraphApiEndpoint = $response.'@odata.nextLink'

        } catch {
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode.value__ } catch {}

            if ($statusCode -eq 429) {
                $retryAfter = 10
                try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                Write-Host -ForegroundColor Red "[*] Rate limited (429). Sleeping ${retryAfter}s..."
                Start-Sleep -Seconds $retryAfter
                # $GraphApiEndpoint stays the same so the loop retries the same page
            } else {
                Write-Host -ForegroundColor Red "[!] Error fetching groups (HTTP $statusCode): $($_.Exception.Message)"
                break
            }
        }
    } while ($GraphApiEndpoint)

    Write-Host -ForegroundColor Green "[*] Enumeration complete: $($allGroups.Count) groups found."

    if ($OutputFile) {
        $allGroups | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host -ForegroundColor Green "[*] Saved to $OutputFile"
    }

    return $allGroups
}


function Test-GraphGroupMemberAccess {
    <#
    .SYNOPSIS
        Checks whether the current user can update members of a supplied list of groups
        by calling the estimateAccess endpoint for each one.

    .DESCRIPTION
        Phase 2 of the two-phase group access audit workflow. Skips group enumeration
        entirely - supply the IDs directly, from a CSV, or from a text file.

        401 (token expiry) is handled reactively: on the first 401 the token is
        refreshed and the same group is retried immediately, rather than silently
        skipping it as Get-UpdatableGroups does.

        429 (rate limiting) respects the Retry-After header.

        Use -Skip N or -StartFromId GUID to resume a partial run without re-checking
        groups that were already processed.

    .PARAMETER GroupIds
        Array of group object IDs (GUIDs) to check directly.

    .PARAMETER InputCsv
        Path to a CSV file with an 'id' column, e.g. output from Get-GraphGroups or
        a previous Get-UpdatableGroups run.

    .PARAMETER InputFile
        Path to a text file with one group ID per line. Also accepts the
        "DisplayName:GUID" format produced by Get-UpdatableGroups intermediate output.

    .PARAMETER Skip
        Skip the first N groups in the resolved list. Use to resume after a known
        failure point, e.g. if the script checked 300 groups before failing pass -Skip 300.

    .PARAMETER StartFromId
        Skip all groups in the list until this group ID is reached, then start from there.
        Useful when you know the exact GUID where the previous run stopped.

    .PARAMETER OutputFile
        CSV file to write updatable groups to. Written once at the end. A fallback
        _ids.txt file is also appended per-group as each result comes in so results
        survive a crash mid-run.
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        # Input sources - provide exactly one
        [Parameter(Mandatory = $false)]
        [string[]]$GroupIds,

        [Parameter(Mandatory = $false)]
        [string]$InputCsv,

        [Parameter(Mandatory = $false)]
        [string]$InputFile,

        # Resume controls
        [Parameter(Mandatory = $false)]
        [int]$Skip = 0,

        [Parameter(Mandatory = $false)]
        [string]$StartFromId,

        # Output
        [string]$OutputFile = "updatable_groups_resumed.csv",

        # Token refresh settings - mirror Get-UpdatableGroups defaults
        [string]$EstimateAccessEndpoint = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess",
        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [String[]]$Client = "MSGraph",
        [String]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [String]$Resource = "https://graph.microsoft.com",
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser = "Edge",
        [Int]$RefreshInterval = 300
    )

    # Resolve group list from whichever input was provided

    $groupList = @()

    if ($GroupIds -and $GroupIds.Count -gt 0) {
        $groupList = @($GroupIds | ForEach-Object {
            [PSCustomObject]@{ id = $_.Trim(); displayName = $_.Trim() }
        })
    } elseif ($InputCsv) {
        if (-not (Test-Path $InputCsv)) {
            Write-Host -ForegroundColor Red "[!] InputCsv not found: $InputCsv"
            return
        }
        $groupList = @(Import-Csv $InputCsv | Where-Object { $_.id } | ForEach-Object {
            [PSCustomObject]@{
                id          = $_.id.Trim()
                displayName = if ($_.displayName) { $_.displayName } else { $_.id }
            }
        })
    } elseif ($InputFile) {
        if (-not (Test-Path $InputFile)) {
            Write-Host -ForegroundColor Red "[!] InputFile not found: $InputFile"
            return
        }
        $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $groupList = @(Get-Content $InputFile | ForEach-Object {
            $line = $_.Trim()
            if ($line -match "^($guidPattern)$") {
                [PSCustomObject]@{ id = $Matches[1]; displayName = $Matches[1] }
            } elseif ($line -match "^(.+):($guidPattern)$") {
                [PSCustomObject]@{ id = $Matches[2]; displayName = $Matches[1] }
            }
        } | Where-Object { $_ })
    } else {
        Write-Host -ForegroundColor Red "[!] Provide -GroupIds, -InputCsv, or -InputFile."
        return
    }

    if ($groupList.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No group IDs resolved from the provided input."
        return
    }

    # Apply resume controls

    if ($StartFromId) {
        $idx = -1
        for ($i = 0; $i -lt $groupList.Count; $i++) {
            if ($groupList[$i].id -eq $StartFromId) { $idx = $i; break }
        }
        if ($idx -lt 0) {
            Write-Host -ForegroundColor Red "[!] -StartFromId '$StartFromId' not found in the group list."
            return
        }
        $groupList = @($groupList[$idx..($groupList.Count - 1)])
        Write-Host -ForegroundColor Yellow "[*] Resuming from '$StartFromId' (index $idx, $($groupList.Count) groups remaining)."
    } elseif ($Skip -gt 0) {
        if ($Skip -ge $groupList.Count) {
            Write-Host -ForegroundColor Red "[!] -Skip $Skip is >= total group count ($($groupList.Count))."
            return
        }
        $groupList = @($groupList[$Skip..($groupList.Count - 1)])
        Write-Host -ForegroundColor Yellow "[*] Skipping first $Skip groups. $($groupList.Count) remaining."
    }

    Write-Host -ForegroundColor Yellow "[*] Checking $($groupList.Count) groups for microsoft.directory/groups/members/update..."

    # Token state

    $accesstoken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        "Authorization" = "Bearer $accesstoken"
        "Content-Type"  = "application/json"
    }

    $startTime        = Get-Date
    $refresh_Interval = [TimeSpan]::FromSeconds($RefreshInterval)

    # Fallback file: append updatable IDs as they are found so results survive a crash
    $fallback = $OutputFile -replace '\.[^.]+$', '_ids.txt'

    $results = @()
    $checked = 0
    $total   = $groupList.Count

    foreach ($group in $groupList) {
        $checked++

        # Proactive token refresh on timer
        if ((Get-Date) - $startTime -ge $refresh_Interval) {
            Write-Host -ForegroundColor Yellow "[*] Proactive token refresh ($checked/$total checked so far)..."
            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                -tenantid $tenantid -Resource $Resource -Client $Client `
                -ClientID $ClientID -Browser $Browser -Device $Device
            if ($global:tokens) {
                $accesstoken  = $global:tokens.access_token
                $refreshToken = $global:tokens.refresh_token
                $headers["Authorization"] = "Bearer $accesstoken"
                $startTime = Get-Date
            }
        }

        $requestBody = @{
            resourceActionAuthorizationChecks = @(
                @{
                    directoryScopeId = "/$($group.id)"
                    resourceAction   = "microsoft.directory/groups/members/update"
                }
            )
        } | ConvertTo-Json -Depth 4

        $maxRetries = 3
        $attempt    = 0
        $done       = $false

        while (-not $done -and $attempt -lt $maxRetries) {
            try {
                $resp = Invoke-RestMethod -Uri $EstimateAccessEndpoint -Headers $headers -Method Post -Body $requestBody
                $done = $true

                if ($resp.value.accessDecision -eq "allowed") {
                    Write-Host -ForegroundColor Green "[+] Updatable: $($group.displayName) ($($group.id))"
                    "$($group.displayName):$($group.id)" | Out-File -Append -Encoding Ascii $fallback
                    $results += [PSCustomObject]@{
                        id          = $group.id
                        displayName = $group.displayName
                        decision    = "allowed"
                    }
                }

            } catch {
                $statusCode = $null
                try { $statusCode = [int]$_.Exception.Response.StatusCode.value__ } catch {}

                if ($statusCode -eq 401) {
                    Write-Host -ForegroundColor Yellow "[*] 401 on '$($group.displayName)' - refreshing token (attempt $($attempt+1)/$maxRetries)..."
                    Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                        -tenantid $tenantid -Resource $Resource -Client $Client `
                        -ClientID $ClientID -Browser $Browser -Device $Device
                    if ($global:tokens) {
                        $accesstoken  = $global:tokens.access_token
                        $refreshToken = $global:tokens.refresh_token
                        $headers["Authorization"] = "Bearer $accesstoken"
                        $startTime = Get-Date
                    }
                    $attempt++
                } elseif ($statusCode -eq 429) {
                    $retryAfter = 10
                    try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                    Write-Host -ForegroundColor Red "[*] 429 on '$($group.displayName)' - sleeping ${retryAfter}s (attempt $($attempt+1)/$maxRetries)..."
                    Start-Sleep -Seconds $retryAfter
                    $attempt++
                } else {
                    Write-Host -ForegroundColor Red "[!] HTTP $statusCode on '$($group.id)': $($_.Exception.Message)"
                    $done = $true
                }
            }
        }

        if (-not $done) {
            Write-Host -ForegroundColor Red "[!] Giving up on '$($group.displayName)' ($($group.id)) after $maxRetries attempts."
            Write-Host -ForegroundColor Yellow "    Resume tip: -StartFromId '$($group.id)'"
        }

        if ($checked % 50 -eq 0) {
            Write-Host -ForegroundColor Cyan "[*] Progress: $checked/$total checked | $($results.Count) updatable found"
        }
    }

    Write-Host -ForegroundColor Green "[*] Done. Checked $checked groups, found $($results.Count) updatable."

    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host -ForegroundColor Green "[*] Results saved to $OutputFile"
        Write-Host -ForegroundColor Green "[*] Fallback ID list at $fallback"
    } else {
        Write-Host -ForegroundColor Yellow "[*] No updatable groups found in this batch."
    }

    return $results
}
