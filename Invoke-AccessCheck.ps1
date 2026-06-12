<#
.SYNOPSIS
    Access checking module for GraphRunner. Enumerates identity posture,
    authentication methods, conditional access policies, and resource access
    for the current token holder or a specified target user or service principal.

.DESCRIPTION
    Sections run per invocation:
      1. Token claims decode  (wids, scp, roles, oid, aud, tid)
      2. Identity profile     (userType, accountEnabled, signInActivity, licenses)
      3. Group & role memberships  (transitive groups, active roles, PIM eligible)
      4. Authentication methods & MFA state  (User) -- or credential expiry (SP)
      5. Conditional Access Policy enumeration
           - MS Graph v1.0 (requires Policy.Read.All + Security/Global Reader role)
           - graph.windows.net 1.61-internal fallback (any token; may be blocked post-2025)
      6. Offline CAP applicability analysis against the target user
      7. CAP What-If simulation  (optional -RunWhatIf; POST endpoint, moderate noise)
      8. App role assignments & OAuth2 delegated permission grants  (User only)
      9. Identity risk state  (IdentityRiskyUser.Read.All; graceful 403 fallback)
     10. Resource token probing  (optional; one sign-in log entry per resource)
     11. Service principal permissions  (SP mode only)
     12. Access summary with flagged findings

.PARAMETER Tokens
    GraphRunner token object (access_token, refresh_token). Defaults to $global:tokens.

.PARAMETER TargetUser
    Optional. User UPN or object ID, or Service Principal object ID / appId.
    Defaults to the identity embedded in the current access token.

.PARAMETER TargetType
    User (default) or ServicePrincipal.

.PARAMETER ResourceId
    Single resource URI to probe for token acquisition (requires refresh token).

.PARAMETER CheckAllResources
    Probe all common resource URIs for token acquisition.
    WARNING: each probe generates one sign-in log entry.

.PARAMETER SkipElevated
    Skip checks that typically require Global/Security Reader roles.

.PARAMETER RunWhatIf
    Run the CAP What-If simulation via POST /identity/conditionalAccess/evaluate.
    Prompts for application ID and optional IP address.

.PARAMETER OutputPath
    If specified, CAPs, probe results, and findings are written to CSV files here.

.EXAMPLE
    . .\GraphRunner\GraphRunner.ps1
    . .\Invoke-AccessCheck.ps1

    Invoke-AccessCheck -Tokens $tokens
    Invoke-AccessCheck -Tokens $tokens -TargetUser "jsmith@contoso.com" -OutputPath .\out
    Invoke-AccessCheck -Tokens $tokens -CheckAllResources
    Invoke-AccessCheck -Tokens $tokens -TargetUser "<sp-object-id>" -TargetType ServicePrincipal
    Invoke-AccessCheck -Tokens $tokens -RunWhatIf

.NOTES
    Requires GraphRunner.ps1 to be dot-sourced first (for Invoke-RefreshGraphTokens
    and Invoke-ForgeUserAgent).
    Encoding: ASCII. Save as ASCII to avoid Windows-1252 parse errors in PS 5.1.
#>


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

function Get-JwtClaims {
    param([string]$Token)
    try {
        $seg = $Token.Split(".")[1]
        $seg = $seg.Replace('-', '+').Replace('_', '/')
        while ($seg.Length % 4) { $seg += "=" }
        return [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String($seg)) | ConvertFrom-Json
    } catch { return $null }
}


function Invoke-GRequest {
    <#
    Graph API call with 401 reactive refresh and 429 back-off.
    $TS keys: AccessToken, RefreshToken, Headers, tenantid, Client, ClientID,
              Resource, Device, Browser.
    Hashtable values are updated in-place on refresh (hashtables are reference types).
    #>
    param(
        [string]$Uri,
        [string]$Method      = "Get",
        [hashtable]$TS,
        [object]$Body        = $null,
        [int]$MaxRetries     = 3
    )

    $attempt = 0
    $done    = $false
    $result  = $null

    while (-not $done -and $attempt -lt $MaxRetries) {
        try {
            $invokeHeaders = @{}
            $TS.Headers.GetEnumerator() | ForEach-Object { $invokeHeaders[$_.Key] = $_.Value }
            if ($Body) { $invokeHeaders["Content-Type"] = "application/json" }

            $params = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $invokeHeaders
                ErrorAction = "Stop"
            }
            if ($Body) { $params.Body = $Body }

            $result = Invoke-RestMethod @params
            $done   = $true
        } catch {
            $sc = $null
            try { $sc = [int]$_.Exception.Response.StatusCode } catch {}
            try { if (-not $sc) { $sc = [int]$_.Exception.Response.StatusCode.value__ } } catch {}

            if ($sc -eq 401) {
                if ($TS.RefreshToken) {
                    Invoke-RefreshGraphTokens -RefreshToken $TS.RefreshToken -AutoRefresh `
                        -tenantid $TS.tenantid -Resource $TS.Resource -Client $TS.Client `
                        -ClientID $TS.ClientID -Browser $TS.Browser -Device $TS.Device
                    if ($global:tokens) {
                        $TS.AccessToken  = $global:tokens.access_token
                        $TS.RefreshToken = $global:tokens.refresh_token
                        $TS.Headers["Authorization"] = "Bearer $($TS.AccessToken)"
                    }
                }
                $attempt++
            } elseif ($sc -eq 429) {
                $wait = 15
                try { $wait = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                Write-Host -ForegroundColor DarkYellow "[*] Rate limited (429) -- sleeping ${wait}s..."
                Start-Sleep -Seconds $wait
            } else {
                $msg = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
                throw [System.Exception]::new("HTTP $sc - $msg")
            }
        }
    }

    if (-not $done) {
        throw [System.Exception]::new("Gave up after $MaxRetries attempts (persistent 401 / token refresh failed)")
    }
    return $result
}


function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host -ForegroundColor Cyan ("=" * 70)
    Write-Host -ForegroundColor Cyan "  $Title"
    Write-Host -ForegroundColor Cyan ("=" * 70)
}


function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Severity,
        [string]$Category,
        [string]$Finding,
        [string]$Detail = ""
    )
    $List.Add([pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Finding  = $Finding
        Detail   = $Detail
    })
}


function Invoke-ResourceTokenProbe {
    <#
    Exchanges a refresh token for the given resource URI via the v1 token endpoint.
    Does NOT touch $global:tokens. Returns a result object with Success, ErrorCode, etc.
    #>
    param(
        [string]$ResourceUri,
        [string]$ResourceName,
        [string]$RefreshToken,
        [string]$ClientId,
        [string]$TenantId
    )

    $endpoint = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $body     = "grant_type=refresh_token" +
                "&refresh_token=$([uri]::EscapeDataString($RefreshToken))" +
                "&resource=$([uri]::EscapeDataString($ResourceUri))" +
                "&client_id=$ClientId"
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $endpoint `
            -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
        return [pscustomobject]@{
            Success          = $true
            ResourceName     = $ResourceName
            ResourceUri      = $ResourceUri
            AccessToken      = $resp.access_token
            ExpiresIn        = $resp.expires_in
            ErrorCode        = $null
            ErrorDescription = $null
        }
    } catch {
        $errCode = $null; $errDesc = $null
        try {
            $eb = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($eb.error_description -match '(AADSTS\d+)') { $errCode = $Matches[1] }
            else { $errCode = $eb.error }
            $errDesc = ($eb.error_description -split '\r?\n')[0]
        } catch {}
        return [pscustomobject]@{
            Success          = $false
            ResourceName     = $ResourceName
            ResourceUri      = $ResourceUri
            AccessToken      = $null
            ExpiresIn        = $null
            ErrorCode        = $errCode
            ErrorDescription = $errDesc
        }
    }
}


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

$script:CommonResources = @(
    [pscustomobject]@{ Name = "MS Graph";            Uri = "https://graph.microsoft.com/" }
    [pscustomobject]@{ Name = "Azure Mgmt (ARM)";    Uri = "https://management.azure.com/" }
    [pscustomobject]@{ Name = "Azure Core Mgmt";     Uri = "https://management.core.windows.net/" }
    [pscustomobject]@{ Name = "SharePoint Online";   Uri = "sharepoint_tenant" }
    [pscustomobject]@{ Name = "Exchange Online";     Uri = "https://outlook.office365.com/" }
    [pscustomobject]@{ Name = "Teams";               Uri = "https://api.spaces.skype.com/" }
    [pscustomobject]@{ Name = "Intune";              Uri = "https://api.manage.microsoft.com/" }
    [pscustomobject]@{ Name = "Office 365 Mgmt API"; Uri = "https://manage.office.com/" }
    [pscustomobject]@{ Name = "Key Vault";           Uri = "https://vault.azure.net/" }
    [pscustomobject]@{ Name = "Power BI";            Uri = "https://analysis.windows.net/powerbi/api" }
    [pscustomobject]@{ Name = "AAD Graph (legacy)";  Uri = "https://graph.windows.net/" }
)

$script:RoleNames = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Exchange Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
    "5d6b6bb7-de71-4623-b4af-96380a352509" = "Security Reader"
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = "Global Reader"
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
    "0526716b-113d-4c15-b2c8-68e3c22b9f80" = "Authentication Administrator"
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Privileged Role Administrator"
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
    "aaf43236-0c0d-4d5f-883a-6955382ac081" = "Authentication Policy Administrator"
    "cf1c38e5-3621-4004-a7cb-879624dced7c" = "Application Developer"
    "744ec460-397e-42ad-a462-8b3f9747a02c" = "Groups Administrator"
    "95e79109-95c0-4d8e-aee3-d01accf2d47b" = "Guest Inviter"
    "17315797-102d-40b4-93e0-432062caca18" = "Compliance Administrator"
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc" = "Power BI Administrator"
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Recipient Administrator"
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = "Directory Readers"
    "9360feb5-f418-4baa-8175-e2a00bac4301" = "Directory Writers"
}

$script:AadErrorHints = @{
    "AADSTS50076"  = "MFA required to acquire token for this resource"
    "AADSTS53003"  = "Blocked by a Conditional Access policy"
    "AADSTS65001"  = "Resource not consented (app not authorized for this resource in tenant)"
    "AADSTS70011"  = "Invalid scope or resource URI"
    "AADSTS50013"  = "Refresh token is expired or has been revoked"
    "AADSTS50058"  = "Silent sign-in required (browser session needed)"
    "AADSTS50055"  = "User password has expired"
    "AADSTS500011" = "Resource principal not found in tenant"
    "AADSTS650057" = "Resource app not provisioned in this tenant"
    "AADSTS700084" = "Refresh token was issued to a SPA client; cannot use for resource exchange"
}


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

function Invoke-AccessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Tokens = $global:tokens,

        [string]$TargetUser = "",

        [ValidateSet("User", "ServicePrincipal")]
        [string]$TargetType = "User",

        [string]$ResourceId = "",

        [switch]$CheckAllResources,
        [switch]$SkipElevated,
        [switch]$RunWhatIf,

        [string]$OutputPath = "",

        [string]$tenantid = $global:tenantid,

        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",

        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",

        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device = "Windows",

        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge"
    )

    # -----------------------------------------------------------------------
    # 0. Validate and bootstrap
    # -----------------------------------------------------------------------

    if (-not $Tokens -or -not $Tokens.access_token) {
        Write-Host -ForegroundColor Red "[!] No tokens available. Pass -Tokens or ensure `$global:tokens is set."
        return
    }

    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        $boot = Get-JwtClaims -Token $Tokens.access_token
        if ($boot -and $boot.appid) {
            $ClientID = $boot.appid
            Write-Host -ForegroundColor Yellow "[*] Auto-detected ClientID from token: $ClientID"
        }
    }

    $TS = @{
        AccessToken  = $Tokens.access_token
        RefreshToken = $Tokens.refresh_token
        Headers      = @{
            Authorization = "Bearer $($Tokens.access_token)"
            Accept        = "application/json"
        }
        tenantid = $tenantid
        Client   = $Client
        ClientID = $ClientID
        Resource = $Resource
        Device   = $Device
        Browser  = $Browser
    }

    $findings          = [System.Collections.Generic.List[object]]::new()
    $registeredMethods = @()

    if ($OutputPath -and -not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory | Out-Null
    }

    # -----------------------------------------------------------------------
    # 1. Token claims decode
    # -----------------------------------------------------------------------

    Write-Section "1. Token Claims"

    $claims = Get-JwtClaims -Token $TS.AccessToken
    if ($null -eq $claims) {
        Write-Host -ForegroundColor Red "[!] Failed to decode access token JWT."
        return
    }

    $tokenOid    = $claims.oid
    $tokenUpn    = if ($claims.upn)         { $claims.upn }
                   elseif ($claims.unique_name) { $claims.unique_name }
                   else                     { $null }
    $tokenTid    = if ($claims.tid)   { $claims.tid }   else { $tenantid }
    $tokenAppId  = $claims.appid
    $tokenAud    = $claims.aud
    $tokenScp    = $claims.scp
    $tokenRoles  = $claims.roles
    $tokenWids   = @(if ($claims.wids) { $claims.wids } else { @() })
    $tokenExpiry = if ($claims.exp) {
        [DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz")
    } else { "N/A" }

    Write-Host -ForegroundColor Yellow "  oid     : $tokenOid"
    Write-Host -ForegroundColor Yellow "  upn     : $(if ($tokenUpn) { $tokenUpn } else { '(absent -- likely app-only token)' })"
    Write-Host -ForegroundColor Yellow "  tid     : $tokenTid"
    Write-Host -ForegroundColor Yellow "  aud     : $tokenAud"
    Write-Host -ForegroundColor Yellow "  appid   : $tokenAppId"
    Write-Host -ForegroundColor Yellow "  expires : $tokenExpiry"

    if ($tokenScp) {
        Write-Host -ForegroundColor Yellow "  scp (delegated scopes):"
        ($tokenScp -split " ") | Sort-Object | ForEach-Object { Write-Host "    $_" }
    }
    if ($tokenRoles) {
        Write-Host -ForegroundColor Yellow "  roles (application permissions in token):"
        $tokenRoles | Sort-Object | ForEach-Object { Write-Host "    $_" }
    }
    if ($tokenWids.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "  wids (directory roles held at token issuance):"
        foreach ($w in $tokenWids) {
            $rn = if ($script:RoleNames.ContainsKey($w)) { " ($($script:RoleNames[$w]))" } else { "" }
            Write-Host "    $w$rn"
        }
    }

    # Propagate tenant ID if not already set
    if ([string]::IsNullOrWhiteSpace($tenantid) -and $tokenTid) {
        $tenantid    = $tokenTid
        $TS.tenantid = $tokenTid
    }

    # Resolve target identity
    $targetId  = ""
    $targetUpn = ""
    $guidRx    = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    if ([string]::IsNullOrWhiteSpace($TargetUser)) {
        $targetId  = $tokenOid
        $targetUpn = $tokenUpn
        Write-Host -ForegroundColor Yellow "[*] No -TargetUser specified; using token identity (oid: $targetId)"
    } elseif ($TargetUser -match $guidRx) {
        $targetId = $TargetUser
    } else {
        $targetUpn = $TargetUser
    }

    $isSelf = ($targetId -and $targetId -eq $tokenOid) -or
              ($targetUpn -and $tokenUpn -and $targetUpn -ieq $tokenUpn)

    $meOrUser = if ($TargetType -eq "ServicePrincipal") {
        "servicePrincipals/$targetId"
    } elseif ($isSelf) {
        "me"
    } elseif ($targetId) {
        "users/$targetId"
    } else {
        "users/$([uri]::EscapeDataString($targetUpn))"
    }

    # -----------------------------------------------------------------------
    # 2. Identity profile
    # -----------------------------------------------------------------------

    Write-Section "2. Identity Profile"

    $targetProfile = $null

    $targetProfileSelect = if ($TargetType -eq "ServicePrincipal") {
        "id,displayName,appId,servicePrincipalType,accountEnabled,appOwnerOrganizationId,keyCredentials,passwordCredentials"
    } else {
        "id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,assignedLicenses,createdDateTime,mail,jobTitle,department"
    }

    $targetProfileBase = if ($TargetType -eq "ServicePrincipal") {
        "https://graph.microsoft.com/v1.0/servicePrincipals/$targetId"
    } else {
        "https://graph.microsoft.com/v1.0/$meOrUser"
    }

    try {
        $targetProfile = Invoke-GRequest -Uri "$targetProfileBase`?`$select=$targetProfileSelect" -TS $TS

        if (-not $targetId -and $targetProfile.id) { $targetId = $targetProfile.id }
        if (-not $targetUpn -and $targetProfile.userPrincipalName) { $targetUpn = $targetProfile.userPrincipalName }

        # Re-anchor meOrUser now that we have the object ID
        $meOrUser = if ($TargetType -eq "ServicePrincipal") { "servicePrincipals/$targetId" }
                    elseif ($isSelf) { "me" }
                    else { "users/$targetId" }

        if ($TargetType -eq "ServicePrincipal") {
            Write-Host -ForegroundColor Green "  displayName          : $($targetProfile.displayName)"
            Write-Host -ForegroundColor Green "  appId                : $($targetProfile.appId)"
            Write-Host -ForegroundColor Green "  servicePrincipalType : $($targetProfile.servicePrincipalType)"
            Write-Host -ForegroundColor Green "  accountEnabled       : $($targetProfile.accountEnabled)"
            Write-Host -ForegroundColor Green "  appOwnerOrganizationId: $($targetProfile.appOwnerOrganizationId)"
            if ($targetProfile.accountEnabled -eq $false) {
                Add-Finding $findings "High" "Identity" "Service principal is disabled" "accountEnabled = false"
            }
        } else {
            $userType = if ($targetProfile.userType) { $targetProfile.userType } else { "Unknown" }
            $synced   = if ($targetProfile.onPremisesSyncEnabled -eq $true) { "Yes (AD synced)" } else { "No (cloud-only)" }
            $licenses = if ($targetProfile.assignedLicenses) { $targetProfile.assignedLicenses.Count } else { 0 }

            Write-Host -ForegroundColor Green "  displayName    : $($targetProfile.displayName)"
            Write-Host -ForegroundColor Green "  UPN            : $($targetProfile.userPrincipalName)"
            Write-Host -ForegroundColor Green "  objectId       : $($targetProfile.id)"
            Write-Host -ForegroundColor Green "  userType       : $userType"
            Write-Host -ForegroundColor Green "  accountEnabled : $($targetProfile.accountEnabled)"
            Write-Host -ForegroundColor Green "  onPremSync     : $synced"
            Write-Host -ForegroundColor Green "  createdDateTime: $($targetProfile.createdDateTime)"
            Write-Host -ForegroundColor Green "  jobTitle       : $($targetProfile.jobTitle)"
            Write-Host -ForegroundColor Green "  department     : $($targetProfile.department)"

            if ($licenses -gt 0) {
                Write-Host -ForegroundColor Green "  licenses       : $licenses assigned"
            } else {
                Write-Host -ForegroundColor Yellow "  licenses       : None"
                Add-Finding $findings "Info" "Identity" "No licenses assigned" "User may not have access to M365 services"
            }
            if ($targetProfile.accountEnabled -eq $false) {
                Add-Finding $findings "High" "Identity" "Account is disabled" "accountEnabled = false"
            }
            if ($userType -eq "Guest") {
                Add-Finding $findings "Medium" "Identity" "Account is a Guest (external) user" "Guest accounts often receive different CAP treatment and reduced default permissions"
            }
        }
    } catch {
        Write-Host -ForegroundColor Red "[!] Failed to retrieve identity profile: $_"
    }

    # Last sign-in (beta, user only; fails silently if no AuditLog.Read.All)
    if ($TargetType -eq "User") {
        try {
            $actResp = Invoke-GRequest -Uri "https://graph.microsoft.com/beta/$meOrUser`?`$select=signInActivity" -TS $TS
            if ($actResp.signInActivity) {
                $lastIA  = $actResp.signInActivity.lastSignInDateTime
                $lastNIA = $actResp.signInActivity.lastNonInteractiveSignInDateTime
                Write-Host -ForegroundColor Green "  lastSignIn (interactive)    : $lastIA"
                Write-Host -ForegroundColor Green "  lastSignIn (non-interactive): $lastNIA"
                if ($lastIA) {
                    $age = ([datetime]::UtcNow - [datetime]$lastIA).Days
                    if ($age -gt 90) {
                        Add-Finding $findings "Info" "Identity" "Dormant account -- last interactive sign-in $age days ago" "Dormant accounts may have reduced monitoring"
                    }
                }
            }
        } catch { }
    }

    if ([string]::IsNullOrWhiteSpace($targetId)) {
        Write-Host -ForegroundColor Red "[!] Could not resolve target object ID. Cannot continue."
        return
    }

    # -----------------------------------------------------------------------
    # 3. Group & role memberships
    # -----------------------------------------------------------------------

    Write-Section "3. Group & Role Memberships"

    $userGroupIds  = @()
    $userRoleIds   = @()

    # Transitive memberships (groups + directory roles)
    try {
        $memberships = @()
        $nextLink    = "https://graph.microsoft.com/v1.0/$meOrUser/transitiveMemberOf?`$select=id,displayName,groupTypes,securityEnabled,isAssignableToRole&`$top=999"
        do {
            $resp        = Invoke-GRequest -Uri $nextLink -TS $TS
            $memberships += @($resp.value)
            $nextLink     = $resp.'@odata.nextLink'
        } while ($nextLink)

        $groups   = @($memberships | Where-Object { $_.'@odata.type' -match 'group' })
        $roleObjs = @($memberships | Where-Object { $_.'@odata.type' -match 'directoryRole' })

        $userGroupIds = @($groups | ForEach-Object { $_.id })

        if ($groups.Count -gt 0) {
            Write-Host -ForegroundColor Green "  Group memberships ($($groups.Count)):"
            foreach ($g in $groups) {
                $flags = @()
                if ($g.isAssignableToRole -eq $true)            { $flags += "role-assignable" }
                if ($g.groupTypes -contains "DynamicMembership") { $flags += "dynamic" }
                $fs = if ($flags.Count -gt 0) { " [$($flags -join ', ')]" } else { "" }
                Write-Host "    - $($g.displayName)  ($($g.id))$fs"
                if ($g.isAssignableToRole -eq $true) {
                    Add-Finding $findings "Medium" "Groups" "Member of role-assignable group: $($g.displayName)" "Role-assignable groups can be used to assign Entra directory roles"
                }
            }
        } else {
            Write-Host -ForegroundColor Yellow "  No transitive group memberships returned"
        }

        foreach ($r in $roleObjs) {
            Write-Host -ForegroundColor Green "  [role via memberOf] $($r.displayName)"
            $userRoleIds += $r.id
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'HTTP 404') {
            Write-Host -ForegroundColor Yellow "  [*] Transitive memberships: 404 Not Found"
            Write-Host -ForegroundColor Yellow "      URL: $nextLink"
            Write-Host -ForegroundColor Yellow "      Verify the target object ID is correct and that the token has User.Read.All, GroupMember.Read.All, or Directory.Read.All; group/role data will be absent from CAP analysis"
        } else {
            Write-Host -ForegroundColor Red "[!] Transitive memberships ($nextLink): $msg"
        }
    }

    # Active directory role assignments
    if (-not $SkipElevated) {
        try {
            $raUri  = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$targetId'&`$expand=roleDefinition"
            $raResp = Invoke-GRequest -Uri $raUri -TS $TS

            if ($raResp.value.Count -gt 0) {
                Write-Host -ForegroundColor Green "  Active directory role assignments ($($raResp.value.Count)):"
                foreach ($ra in $raResp.value) {
                    $rn    = if ($ra.roleDefinition) { $ra.roleDefinition.displayName } else { $ra.roleDefinitionId }
                    $scope = if ($ra.directoryScopeId -eq "/") { "Tenant-wide" } else { $ra.directoryScopeId }
                    Write-Host -ForegroundColor Green "    [+] $rn  --  scope: $scope"
                    $userRoleIds += $ra.roleDefinitionId
                    Add-Finding $findings "High" "Roles" "Active directory role: $rn" "Scope: $scope"
                }
            } else {
                Write-Host -ForegroundColor Yellow "  No active directory role assignments found"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] Role assignments (RoleManagement.Read.Directory required): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }

        # PIM eligible roles
        try {
            $pimUri  = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$targetId'&`$expand=roleDefinition"
            $pimResp = Invoke-GRequest -Uri $pimUri -TS $TS

            if ($pimResp.value.Count -gt 0) {
                Write-Host -ForegroundColor Yellow "  PIM eligible roles (NOT currently active) ($($pimResp.value.Count)):"
                foreach ($pr in $pimResp.value) {
                    $rn  = if ($pr.roleDefinition) { $pr.roleDefinition.displayName } else { $pr.roleDefinitionId }
                    $exp = if ($pr.scheduleInfo.expiration.endDateTime) { "expires $($pr.scheduleInfo.expiration.endDateTime)" } else { "no expiry" }
                    Write-Host -ForegroundColor Yellow "    [~] $rn  ($exp)"
                    Add-Finding $findings "High" "Roles" "PIM eligible role: $rn (not currently active)" "If activated, grants $rn; $exp"
                }
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] PIM eligible roles (RoleEligibilitySchedule.Read.Directory required): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }
    }

    $userRoleIds = @($userRoleIds | Sort-Object -Unique)

    # wids in token = roles held at issuance time
    if ($tokenWids.Count -gt 0 -and $isSelf) {
        Write-Host -ForegroundColor Yellow "  wids in current token (snapshot at issuance -- may differ from live):"
        foreach ($w in $tokenWids) {
            $rn = if ($script:RoleNames.ContainsKey($w)) { $script:RoleNames[$w] } else { $w }
            Write-Host "    $rn"
        }
        # Merge wids into role IDs for CAP analysis
        $userRoleIds = @($userRoleIds + $tokenWids | Sort-Object -Unique)
    }

    # -----------------------------------------------------------------------
    # 4. Authentication methods & MFA state  (User)  /  Credentials (SP)
    # -----------------------------------------------------------------------

    if ($TargetType -eq "User") {
        Write-Section "4. Authentication Methods & MFA State"

        $authBase = "https://graph.microsoft.com/v1.0/$meOrUser/authentication"
        $betaBase = "https://graph.microsoft.com/beta/$meOrUser/authentication"

        $hasAuthenticator        = $false; $hasFido2  = $false; $hasPhone      = $false
        $hasTap                  = $false; $hasWindowsHello = $false; $hasEmail = $false
        $mfaEnumerationSucceeded = $false

        # All registered methods
        try {
            $methodsResp             = Invoke-GRequest -Uri "$authBase/methods" -TS $TS
            $registeredMethods       = @($methodsResp.value)
            $mfaEnumerationSucceeded = $true

            if ($registeredMethods.Count -eq 0) {
                Write-Host -ForegroundColor Red "  [!] No MFA methods registered"
                Add-Finding $findings "Critical" "MFA" "No authentication methods registered" "User cannot satisfy MFA requirements; sign-in may succeed without MFA"
            } else {
                Write-Host -ForegroundColor Green "  Registered authentication methods ($($registeredMethods.Count)):"
                foreach ($m in $registeredMethods) {
                    $mt = $m.'@odata.type' -replace '#microsoft\.graph\.', ''
                    switch -Wildcard ($mt) {
                        "*microsoftAuthenticator*" { $hasAuthenticator = $true }
                        "*fido2*"                  { $hasFido2         = $true }
                        "*phone*"                  { $hasPhone         = $true }
                        "*softwareOath*"           { }
                        "*temporaryAccessPass*"    { $hasTap           = $true }
                        "*windowsHelloForBusiness*"{ $hasWindowsHello  = $true }
                        "*email*"                  { $hasEmail         = $true }
                    }
                    $detail = switch -Wildcard ($mt) {
                        "*phone*" { "  [$($m.phoneNumber) / $($m.phoneType)]" }
                        "*email*" { "  [$($m.emailAddress)]" }
                        "*fido2*" { "  [$($m.displayName)]" }
                        default   { "" }
                    }
                    Write-Host "    - $mt$detail"
                }

                if ($hasTap) {
                    Write-Host -ForegroundColor Red "  [!] FINDING: Active Temporary Access Pass detected"
                    Add-Finding $findings "High" "MFA" "Temporary Access Pass (TAP) is registered and active" "TAP bypasses MFA entirely; investigate if expected"
                }
                if ($hasFido2 -or $hasWindowsHello) {
                    Write-Host -ForegroundColor Green "  [+] Phishing-resistant method registered (FIDO2 / Windows Hello)"
                } elseif (-not $hasAuthenticator) {
                    Add-Finding $findings "Medium" "MFA" "No phishing-resistant MFA method registered" "User only has phone/SMS/OATH methods which are phishable"
                }
                if ($hasPhone -and -not $hasAuthenticator -and -not $hasFido2) {
                    Add-Finding $findings "Medium" "MFA" "Only SMS/voice phone MFA registered" "SMS MFA is susceptible to SIM-swap and SS7 attacks"
                }
                if ($hasEmail -and -not $hasAuthenticator -and -not $hasFido2 -and -not $hasPhone -and -not $hasWindowsHello) {
                    Add-Finding $findings "High" "MFA" "Only email authentication method registered" "Email is the weakest MFA method; susceptible to account takeover if the user's email is compromised"
                }
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] Auth methods (UserAuthenticationMethod.Read.All required for non-self): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }

        # Sign-in preferences (beta -- fail silently)
        try {
            $pref = Invoke-GRequest -Uri "$betaBase/signInPreferences" -TS $TS
            Write-Host -ForegroundColor Green "  System-preferred MFA enabled : $($pref.isSystemPreferredAuthenticationMethodEnabled)"
            Write-Host -ForegroundColor Green "  User preferred method        : $($pref.userPreferredMethodForSecondaryAuthentication)"
        } catch { }

        # Per-user legacy MFA state (beta, elevated)
        if (-not $SkipElevated) {
            try {
                $req        = Invoke-GRequest -Uri "$betaBase/requirements" -TS $TS
                $perUserMfa = $req.perUserMfaState
                $mfaColor   = switch ($perUserMfa) { "enforced" { "Green" }; "enabled" { "Yellow" }; "disabled" { "Red" }; default { "Yellow" } }
                Write-Host -ForegroundColor $mfaColor "  Legacy per-user MFA state    : $perUserMfa"
                if ($perUserMfa -eq "disabled") {
                    Add-Finding $findings "Medium" "MFA" "Legacy per-user MFA is disabled" "MFA enforcement relies solely on Conditional Access policies"
                }
            } catch {
                Write-Host -ForegroundColor Yellow "  [*] Per-user MFA requirements (beta, elevated read required): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
            }
        }

    } else {
        # SP credential expiry check
        Write-Section "4. Service Principal Credentials"
        $now = [datetime]::UtcNow

        if ($targetProfile) {
            $certs   = @($targetProfile.keyCredentials)
            $secrets = @($targetProfile.passwordCredentials)

            if ($certs.Count -gt 0) {
                Write-Host -ForegroundColor Green "  Certificates ($($certs.Count)):"
                foreach ($c in $certs) {
                    $exp     = if ($c.endDateTime) { [datetime]$c.endDateTime } else { $null }
                    $expired = $exp -and $exp -lt $now
                    $col     = if ($expired) { "Red" } else { "Green" }
                    Write-Host -ForegroundColor $col "    - $($c.displayName)  type:$($c.type)  expires:$($c.endDateTime)$(if ($expired) { '  [EXPIRED]' })"
                    if ($expired) { Add-Finding $findings "Medium" "Credentials" "Expired certificate: $($c.displayName)" "Expired $($c.endDateTime)" }
                }
            }
            if ($secrets.Count -gt 0) {
                Write-Host -ForegroundColor Green "  Client secrets ($($secrets.Count)) -- values not retrievable:"
                foreach ($s in $secrets) {
                    $exp     = if ($s.endDateTime) { [datetime]$s.endDateTime } else { $null }
                    $expired = $exp -and $exp -lt $now
                    $col     = if ($expired) { "Red" } else { "Green" }
                    Write-Host -ForegroundColor $col "    - $($s.displayName)  expires:$($s.endDateTime)$(if ($expired) { '  [EXPIRED]' })"
                    if ($expired) { Add-Finding $findings "Medium" "Credentials" "Expired client secret: $($s.displayName)" "Expired $($s.endDateTime)" }
                }
            }
            if ($certs.Count -eq 0 -and $secrets.Count -eq 0) {
                Write-Host -ForegroundColor Yellow "  No certificates or client secrets found"
                Add-Finding $findings "Info" "Credentials" "SP has no credentials" "May rely on federated identity or managed identity"
            }
        }
    }

    # -----------------------------------------------------------------------
    # 5. Conditional Access Policy enumeration
    # -----------------------------------------------------------------------

    Write-Section "5. Conditional Access Policies"

    $allPolicies = @()
    $capSource   = ""

    if (-not $SkipElevated) {

        # Path A: MS Graph v1.0 (requires Policy.Read.All + Security/Global Reader role)
        try {
            $capResp     = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=999" -TS $TS
            $allPolicies = @($capResp.value)
            $nl          = $capResp.'@odata.nextLink'
            while ($nl) {
                $p = Invoke-GRequest -Uri $nl -TS $TS
                $allPolicies += @($p.value)
                $nl = $p.'@odata.nextLink'
            }
            $capSource = "MS Graph v1.0"
            Write-Host -ForegroundColor Green "[+] Retrieved $($allPolicies.Count) CAP(s) via MS Graph"
        } catch {
            Write-Host -ForegroundColor Yellow "[*] MS Graph CAP path failed (Policy.Read.All + Security Reader role required): $($_.Exception.Message -replace 'HTTP \d+ - ','')"

            # Path B: graph.windows.net 1.61-internal (any token; likely blocked post-mid-2025)
            Write-Host -ForegroundColor Yellow "[*] Attempting graph.windows.net 1.61-internal fallback..."
            if ($TS.RefreshToken) {
                $tid = if ($tenantid) { $tenantid } else { $tokenTid }
                $aadProbe = Invoke-ResourceTokenProbe `
                    -ResourceUri  "https://graph.windows.net/" `
                    -ResourceName "AAD Graph (legacy)" `
                    -RefreshToken  $TS.RefreshToken `
                    -ClientId      $TS.ClientID `
                    -TenantId      $tid

                if ($aadProbe.Success -and $aadProbe.AccessToken) {
                    try {
                        $fbUri  = "https://graph.windows.net/$tid/policies?api-version=1.61-internal"
                        $fbResp = Invoke-RestMethod -Method Get -Uri $fbUri `
                            -Headers @{ Authorization = "Bearer $($aadProbe.AccessToken)"; Accept = "application/json" } `
                            -ErrorAction Stop

                        # AAD Graph wraps policies under .value; filter to CAP type (policyType 18)
                        $legacyPolicies = @($fbResp.value | Where-Object {
                            $_.policyType -eq "18" -or
                            ($_.policyDetail -and $_.policyDetail[0] -match "ConditionalAccessPolicy")
                        })
                        $allPolicies = $legacyPolicies
                        $capSource   = "graph.windows.net 1.61-internal (legacy)"
                        Write-Host -ForegroundColor Green "[+] Retrieved $($allPolicies.Count) CAP(s) via graph.windows.net fallback"
                        Add-Finding $findings "Info" "CAP" "graph.windows.net 1.61-internal is still accessible in this tenant" "Tenant has not fully completed AAD Graph retirement"
                    } catch {
                        Write-Host -ForegroundColor Red "[!] graph.windows.net policy query failed: $($_.Exception.Message -replace 'HTTP \d+ - ','')"
                    }
                } else {
                    Write-Host -ForegroundColor Red "[!] Could not acquire AAD Graph token: $($aadProbe.ErrorCode) -- $($aadProbe.ErrorDescription)"
                    Write-Host -ForegroundColor Yellow "[*] Note: graph.windows.net has been retired since mid-2025; this is expected in most tenants."
                }
            } else {
                Write-Host -ForegroundColor Yellow "[*] No refresh token available for AAD Graph fallback."
            }
        }

        # Summary
        $enabledPolicies    = @($allPolicies | Where-Object { $_.state -eq "enabled" })
        $reportOnlyPolicies = @($allPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })
        $disabledPolicies   = @($allPolicies | Where-Object { $_.state -eq "disabled" })

        if ($allPolicies.Count -gt 0) {
            Write-Host -ForegroundColor Green "  Total     : $($allPolicies.Count)  (source: $capSource)"
            Write-Host -ForegroundColor Green "  Enabled   : $($enabledPolicies.Count)"
            Write-Host -ForegroundColor Yellow "  Report-only: $($reportOnlyPolicies.Count)"
            Write-Host -ForegroundColor Yellow "  Disabled  : $($disabledPolicies.Count)"

            if ($OutputPath) {
                $capCsv = Join-Path $OutputPath "ConditionalAccessPolicies.csv"
                $allPolicies | ForEach-Object {
                    [pscustomobject]@{
                        Id              = $_.id
                        DisplayName     = $_.displayName
                        State           = $_.state
                        IncludeUsers    = ($_.conditions.users.includeUsers    -join "; ")
                        ExcludeUsers    = ($_.conditions.users.excludeUsers    -join "; ")
                        IncludeGroups   = ($_.conditions.users.includeGroups   -join "; ")
                        ExcludeGroups   = ($_.conditions.users.excludeGroups   -join "; ")
                        IncludeRoles    = ($_.conditions.users.includeRoles    -join "; ")
                        ExcludeRoles    = ($_.conditions.users.excludeRoles    -join "; ")
                        IncludeApps     = ($_.conditions.applications.includeApplications -join "; ")
                        ExcludeApps     = ($_.conditions.applications.excludeApplications -join "; ")
                        ClientAppTypes  = ($_.conditions.clientAppTypes -join "; ")
                        GrantControls   = ($_.grantControls.builtInControls -join "; ")
                        AuthStrength    = $_.grantControls.authenticationStrength.displayName
                        SignInFrequency = if ($_.sessionControls.signInFrequency) {
                            "$($_.sessionControls.signInFrequency.value) $($_.sessionControls.signInFrequency.type)"
                        } else { "" }
                    }
                } | Export-Csv -Path $capCsv -NoTypeInformation -Encoding UTF8
                Write-Host -ForegroundColor Green "[*] CAPs exported to $capCsv"
            }
        } else {
            Write-Host -ForegroundColor Yellow "  [*] No policies retrieved (insufficient permissions, or no policies exist)"
        }
    } else {
        Write-Host -ForegroundColor Yellow "[*] Skipping CAP enumeration (-SkipElevated)"
        $enabledPolicies    = @()
        $reportOnlyPolicies = @()
        $disabledPolicies   = @()
    }

    # -----------------------------------------------------------------------
    # 6. CAP applicability analysis (offline, user only)
    # -----------------------------------------------------------------------

    if ($allPolicies.Count -gt 0 -and $TargetType -eq "User") {
        $targetLabel = if ($targetUpn) { $targetUpn } else { $targetId }
        Write-Section "6. CAP Applicability Analysis -- $targetLabel"

        $applicablePolicies    = [System.Collections.Generic.List[object]]::new()
        $notApplicablePolicies = [System.Collections.Generic.List[object]]::new()
        $hasMfaEnforcement     = $false
        $excludedFromAll       = ($enabledPolicies.Count -gt 0)

        foreach ($pol in $enabledPolicies) {
            $cu       = $pol.conditions.users
            $included = $false
            $excluded = $false

            # Inclusion
            if     ($cu.includeUsers -contains "All")                                                   { $included = $true }
            elseif ($cu.includeUsers -contains "GuestsOrExternalUsers" -and $targetProfile -and $targetProfile.userType -eq "Guest") { $included = $true }
            elseif ($targetId  -and $cu.includeUsers -contains $targetId)                               { $included = $true }
            elseif ($targetUpn -and $cu.includeUsers -contains $targetUpn)                              { $included = $true }
            elseif ($userGroupIds.Count -gt 0 -and
                    @($cu.includeGroups | Where-Object { $userGroupIds -contains $_ }).Count -gt 0)     { $included = $true }
            elseif ($userRoleIds.Count  -gt 0 -and
                    @($cu.includeRoles  | Where-Object { $userRoleIds  -contains $_ }).Count -gt 0)     { $included = $true }

            # Exclusion
            if     ($targetId  -and $cu.excludeUsers -contains $targetId)                               { $excluded = $true }
            elseif ($targetUpn -and $cu.excludeUsers -contains $targetUpn)                              { $excluded = $true }
            elseif ($userGroupIds.Count -gt 0 -and
                    @($cu.excludeGroups | Where-Object { $userGroupIds -contains $_ }).Count -gt 0)     { $excluded = $true }
            elseif ($userRoleIds.Count  -gt 0 -and
                    @($cu.excludeRoles  | Where-Object { $userRoleIds  -contains $_ }).Count -gt 0)     { $excluded = $true }

            $applies = $included -and -not $excluded

            $grants   = @(if ($pol.grantControls) { $pol.grantControls.builtInControls } else { @() })
            $reqMfa   = $grants -contains "mfa"
            $reqComp  = $grants -contains "compliantDevice"
            $reqDj    = $grants -contains "domainJoinedDevice"
            $authStr  = $pol.grantControls.authenticationStrength.displayName

            if ($applies) {
                $excludedFromAll    = $false
                $hasMfaEnforcement  = $hasMfaEnforcement -or $reqMfa -or ($null -ne $authStr -and $authStr -ne "")

                $applicablePolicies.Add([pscustomobject]@{
                    DisplayName        = $pol.displayName
                    RequiresMfa        = $reqMfa
                    RequiresCompliance = $reqComp
                    RequiresDomainJoin = $reqDj
                    AuthStrength       = $authStr
                    IncludeApps        = ($pol.conditions.applications.includeApplications -join "; ")
                    ClientAppTypes     = ($pol.conditions.clientAppTypes -join "; ")
                    IncludeLocations   = ($pol.conditions.locations.includeLocations -join "; ")
                    SignInRisk         = ($pol.conditions.signInRiskLevels -join "; ")
                    UserRisk           = ($pol.conditions.userRiskLevels -join "; ")
                })
            } else {
                $reason = if (-not $included) { "not in user/group/role scope" } else { "explicitly excluded" }
                $notApplicablePolicies.Add([pscustomobject]@{
                    DisplayName = $pol.displayName
                    Reason      = $reason
                    Excluded    = $excluded
                    Disabled    = $false
                })
            }
        }

        # Include report-only and disabled policies in the not-applying list
        foreach ($pol in $reportOnlyPolicies) {
            $notApplicablePolicies.Add([pscustomobject]@{
                DisplayName = $pol.displayName
                Reason      = "Report-only (not enforced)"
                Excluded    = $false
                Disabled    = $false
            })
        }
        foreach ($pol in $disabledPolicies) {
            $notApplicablePolicies.Add([pscustomobject]@{
                DisplayName = $pol.displayName
                Reason      = "Policy is disabled"
                Excluded    = $false
                Disabled    = $true
            })
        }

        Write-Host -ForegroundColor Green "  Enabled policies applicable to target : $($applicablePolicies.Count)"
        Write-Host -ForegroundColor Yellow "  Policies NOT applying to target       : $($notApplicablePolicies.Count)"

        if ($applicablePolicies.Count -gt 0) {
            Write-Host ""
            Write-Host -ForegroundColor Green "  Applicable policies:"
            foreach ($p in $applicablePolicies) {
                $gc = @()
                if ($p.RequiresMfa)        { $gc += "MFA" }
                if ($p.RequiresCompliance) { $gc += "CompliantDevice" }
                if ($p.RequiresDomainJoin) { $gc += "DomainJoined" }
                if ($p.AuthStrength)       { $gc += "AuthStrength: $($p.AuthStrength)" }
                if ($gc.Count -eq 0)       { $gc += "No grant control (session control only?)" }

                Write-Host "    [+] $($p.DisplayName)"
                Write-Host "         Apps      : $($p.IncludeApps)"
                Write-Host "         Grant     : $($gc -join ' + ')"
                if ($p.ClientAppTypes) { Write-Host "         ClientApp : $($p.ClientAppTypes)" }
                if ($p.SignInRisk)     { Write-Host "         SignInRisk: $($p.SignInRisk)" }
                if ($p.UserRisk)       { Write-Host "         UserRisk  : $($p.UserRisk)" }
                if ($p.IncludeLocations) { Write-Host "         Locations : $($p.IncludeLocations)" }
            }
        }

        if ($notApplicablePolicies.Count -gt 0) {
            Write-Host ""
            Write-Host -ForegroundColor Yellow "  Policies NOT applying to target:"
            foreach ($p in ($notApplicablePolicies | Sort-Object @{e='Excluded';desc=$true}, @{e='Disabled';desc=$false})) {
                $flag = if ($p.Excluded) { "  [EXCLUDED]" } else { "" }
                $col  = if ($p.Excluded) { "Red" } elseif ($p.Disabled) { "DarkGray" } else { "Yellow" }
                Write-Host -ForegroundColor $col "    [-] $($p.DisplayName) -- $($p.Reason)$flag"
                if ($p.Excluded) {
                    Add-Finding $findings "High" "CAP" "Target is EXCLUDED from policy: $($p.DisplayName)" "Explicit exclusion bypasses this policy's controls"
                }
            }
        }

        # Key CAP findings
        if ($excludedFromAll) {
            Add-Finding $findings "Critical" "CAP" "Target is excluded from ALL enabled Conditional Access policies" "Possible break-glass / over-privileged exclusion; no CAP controls apply to this identity"
        }
        if (-not $hasMfaEnforcement -and $enabledPolicies.Count -gt 0) {
            Add-Finding $findings "High" "CAP" "No applicable enabled CAP enforces MFA for this user" "Sign-in without MFA may be possible depending on app and legacy per-user MFA state"
        }
        if ($hasMfaEnforcement -and $mfaEnumerationSucceeded -and $registeredMethods.Count -eq 0) {
            Add-Finding $findings "Critical" "CAP" "MFA is required by CAP but user has no registered MFA methods" "Authentication will likely fail or fall back unexpectedly"
        } elseif ($hasMfaEnforcement -and -not $mfaEnumerationSucceeded) {
            Add-Finding $findings "Info" "CAP" "MFA is required by CAP but authentication methods could not be enumerated (403 Forbidden)" "Manually verify MFA registration for this user; UserAuthenticationMethod.Read.All is required"
        }

        # Check for legacy auth coverage
        $legacyBlocked = @($applicablePolicies | Where-Object { $_.ClientAppTypes -match "exchangeActiveSync|other" })
        if ($legacyBlocked.Count -eq 0) {
            Add-Finding $findings "Medium" "CAP" "No applicable CAP restricts legacy authentication client types" "Legacy auth (EAS, IMAP, SMTP AUTH, POP3) may bypass MFA requirements"
        }
    }

    # -----------------------------------------------------------------------
    # 7. CAP What-If simulation
    # -----------------------------------------------------------------------

    if ($RunWhatIf -and -not $SkipElevated) {
        Write-Section "7. CAP What-If Simulation"

        Write-Host -ForegroundColor Cyan "[*] Application ID to simulate (GUID, 'All', or press Enter for MS Graph):"
        $wiApp = Read-Host
        if ([string]::IsNullOrWhiteSpace($wiApp)) { $wiApp = "00000003-0000-0000-c000-000000000000" }

        Write-Host -ForegroundColor Cyan "[*] IP address to simulate (or Enter to omit):"
        $wiIp = Read-Host

        $wiBody = @{
            signInIdentity = @{
                "@odata.type" = "#microsoft.graph.signInUser"
                userId        = $targetId
            }
            signInContext = @{
                includeApplications = @($(if ($wiApp -eq "All") { "All" } else { $wiApp }))
            }
            appliedPoliciesOnly = $false
        }
        if ($wiIp) { $wiBody.signInConditions = @{ ipAddress = $wiIp } }

        try {
            $wiResp = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate" `
                -Method "Post" -Body ($wiBody | ConvertTo-Json -Depth 10) -TS $TS

            Write-Host -ForegroundColor Green "[+] What-If results ($($wiResp.value.Count) policies evaluated):"
            foreach ($wr in $wiResp.value) {
                $applies = $wr.matchState -eq "match"
                $col     = if ($applies) { "Green" } else { "Yellow" }
                $tag     = if ($applies) { "[APPLIES]" } else { "[skip]" }
                Write-Host -ForegroundColor $col "  $tag $($wr.displayName)"
                if (-not $applies -and $wr.analysisReasons) {
                    Write-Host "        Reasons: $($wr.analysisReasons -join ', ')"
                }
            }
        } catch {
            Write-Host -ForegroundColor Red "[!] What-If simulation failed: $($_.Exception.Message -replace 'HTTP \d+ - ','')"
            Write-Host -ForegroundColor Yellow "[*] Requires Policy.Read.ConditionalAccess (or Policy.Read.All) + Security Reader role"
        }
    }

    # -----------------------------------------------------------------------
    # 8. App role assignments & OAuth2 permission grants  (User only)
    # -----------------------------------------------------------------------

    if ($TargetType -eq "User") {
        Write-Section "8. App Role Assignments & OAuth2 Permission Grants"

        # App roles assigned to the user in enterprise apps
        try {
            $arUri  = "https://graph.microsoft.com/v1.0/$meOrUser/appRoleAssignments"
            $arResp = Invoke-GRequest -Uri $arUri -TS $TS
            $arList = @($arResp.value)
            if ($arList.Count -gt 0) {
                Write-Host -ForegroundColor Green "  App role assignments ($($arList.Count)):"
                foreach ($ar in $arList) {
                    Write-Host "    - $($ar.resourceDisplayName)  |  roleId: $($ar.appRoleId)"
                }
            } else {
                Write-Host -ForegroundColor Yellow "  No app role assignments found"
            }
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'HTTP 404') {
                Write-Host -ForegroundColor Yellow "  [*] App role assignments: 404 Not Found"
                Write-Host -ForegroundColor Yellow "      URL: $arUri"
                Write-Host -ForegroundColor Yellow "      Verify the target object ID is correct and that the token has AppRoleAssignment.ReadWrite.All or Directory.Read.All"
            } else {
                Write-Host -ForegroundColor Yellow "  [*] App role assignments ($arUri): $($msg -replace 'HTTP \d+ - ','')"
            }
        }

        # OAuth2 delegated permission grants (clients that can act as this user)
        try {
            $grResp = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=principalId eq '$targetId'" -TS $TS
            $grants = @($grResp.value)
            if ($grants.Count -gt 0) {
                Write-Host -ForegroundColor Green "  OAuth2 delegated permission grants ($($grants.Count)):"
                foreach ($g in $grants) {
                    $scope = if ($g.scope) { $g.scope.Trim() } else { "(none)" }
                    Write-Host "    - clientId:$($g.clientId)  resourceId:$($g.resourceId)  consent:$($g.consentType)"
                    Write-Host "      scope: $scope"
                    if ($g.consentType -eq "AllPrincipals") {
                        Add-Finding $findings "Medium" "Permissions" "Admin-consented (AllPrincipals) OAuth2 grant found" "Client $($g.clientId) can act as ANY user; scope: $scope"
                    }
                }
            } else {
                Write-Host -ForegroundColor Yellow "  No OAuth2 delegated permission grants found"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] OAuth2 grants (Directory.Read.All required for non-self targets): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }
    }

    # -----------------------------------------------------------------------
    # 9. Identity risk state  (User only)
    # -----------------------------------------------------------------------

    if (-not $SkipElevated -and $TargetType -eq "User") {
        Write-Section "9. Identity Risk State"

        try {
            $riskResp   = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/$targetId" -TS $TS
            $riskLevel  = $riskResp.riskLevel
            $riskState  = $riskResp.riskState
            $riskDetail = $riskResp.riskDetail
            $rCol       = switch ($riskLevel) { "high" { "Red" }; "medium" { "Yellow" }; "low" { "Yellow" }; default { "Green" } }

            Write-Host -ForegroundColor $rCol "  Risk level  : $riskLevel"
            Write-Host -ForegroundColor $rCol "  Risk state  : $riskState"
            Write-Host -ForegroundColor $rCol "  Risk detail : $riskDetail"

            if ($riskLevel -in @("high","medium")) {
                Add-Finding $findings "High" "IdentityRisk" "User has elevated risk level: $riskLevel" "State: $riskState | Detail: $riskDetail"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] Risk state (IdentityRiskyUser.Read.All required): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }
    }

    # -----------------------------------------------------------------------
    # 10. Resource token probing
    # -----------------------------------------------------------------------

    if ($CheckAllResources -or $ResourceId) {
        Write-Section "10. Resource Token Probing"
        Write-Host -ForegroundColor Red "  [!] WARNING: Each successful or failed probe generates a sign-in log entry."

        if (-not $TS.RefreshToken) {
            Write-Host -ForegroundColor Red "  [!] No refresh token available. Skipping."
        } else {
            $tid = if ($tenantid) { $tenantid } else { $tokenTid }

            if ($ResourceId) {
                $resourcesToProbe = @([pscustomobject]@{ Name = "Custom"; Uri = $ResourceId })
            } else {
                # Resolve tenant-specific SharePoint URI from UPN domain
                $resourcesToProbe = @()
                foreach ($r in $script:CommonResources) {
                    $uri = $r.Uri
                    if ($uri -eq "sharepoint_tenant") {
                        if ($tokenUpn -and $tokenUpn -match "@([^@]+)$") {
                            $dom  = $Matches[1]
                            $base = ($dom -split '\.')[0]
                            $uri  = "https://$base.sharepoint.com/"
                        } else {
                            Write-Host -ForegroundColor Yellow "  [*] Cannot determine SharePoint URL (no UPN in token). Skipping SharePoint probe."
                            continue
                        }
                    }
                    $resourcesToProbe += [pscustomobject]@{ Name = $r.Name; Uri = $uri }
                }
            }

            $probeResults = [System.Collections.Generic.List[object]]::new()

            foreach ($r in $resourcesToProbe) {
                Write-Host -NoNewline "  $($r.Name.PadRight(32))"
                $probe = Invoke-ResourceTokenProbe `
                    -ResourceUri  $r.Uri `
                    -ResourceName $r.Name `
                    -RefreshToken  $TS.RefreshToken `
                    -ClientId      $TS.ClientID `
                    -TenantId      $tid

                if ($probe.Success) {
                    Write-Host -ForegroundColor Green " [OK]  token acquired (expires in $($probe.ExpiresIn)s)"
                } else {
                    $hint = if ($probe.ErrorCode -and $script:AadErrorHints.ContainsKey($probe.ErrorCode)) {
                        " -- $($script:AadErrorHints[$probe.ErrorCode])"
                    } else { "" }
                    $col = if ($probe.ErrorCode -eq "AADSTS53003") { "Red" } else { "Yellow" }
                    Write-Host -ForegroundColor $col " [FAIL] $($probe.ErrorCode)$hint"
                }

                $hint2 = if ($probe.ErrorCode -and $script:AadErrorHints.ContainsKey($probe.ErrorCode)) { $script:AadErrorHints[$probe.ErrorCode] } else { $probe.ErrorDescription }
                $probeResults.Add([pscustomobject]@{
                    ResourceName     = $probe.ResourceName
                    ResourceUri      = $probe.ResourceUri
                    TokenAcquired    = $probe.Success
                    ErrorCode        = $probe.ErrorCode
                    Hint             = $hint2
                })

                if ($probe.ErrorCode -eq "AADSTS53003") {
                    Add-Finding $findings "Info" "ResourceAccess" "CAP blocks token acquisition for: $($r.Name)" "AADSTS53003 -- a Conditional Access policy is explicitly blocking this resource"
                }
            }

            if ($OutputPath) {
                $probeCsv = Join-Path $OutputPath "ResourceProbeResults.csv"
                $probeResults | Export-Csv -Path $probeCsv -NoTypeInformation -Encoding UTF8
                Write-Host -ForegroundColor Green "[*] Probe results exported to $probeCsv"
            }
        }
    }

    # -----------------------------------------------------------------------
    # 11. Service principal permissions  (SP mode only)
    # -----------------------------------------------------------------------

    if ($TargetType -eq "ServicePrincipal") {
        Write-Section "11. Service Principal Permissions"

        # App roles granted to this SP on other resources
        try {
            $spRaResp = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$targetId/appRoleAssignments" -TS $TS
            $spRoles  = @($spRaResp.value)
            if ($spRoles.Count -gt 0) {
                Write-Host -ForegroundColor Green "  App roles granted to this SP ($($spRoles.Count)):"
                foreach ($r in $spRoles) {
                    Write-Host "    - $($r.resourceDisplayName)  roleId:$($r.appRoleId)"
                }
            } else {
                Write-Host -ForegroundColor Yellow "  No app roles granted to this SP"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] SP app role assignments: $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }

        # Admin-consented delegated grants
        try {
            $spGrResp = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$targetId/oauth2PermissionGrants" -TS $TS
            $spGrants = @($spGrResp.value)
            if ($spGrants.Count -gt 0) {
                Write-Host -ForegroundColor Green "  Admin-consented delegated grants ($($spGrants.Count)):"
                foreach ($g in $spGrants) {
                    Write-Host "    - consentType:$($g.consentType)  resourceId:$($g.resourceId)  scope:$($g.scope)"
                }
            } else {
                Write-Host -ForegroundColor Yellow "  No admin-consented delegated grants found"
            }
        } catch {
            Write-Host -ForegroundColor Yellow "  [*] SP delegated grants: $($_.Exception.Message -replace 'HTTP \d+ - ','')"
        }

        # Owners
        try {
            $owResp = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$targetId/owners?`$select=id,displayName,userPrincipalName" -TS $TS
            $owners = @($owResp.value)
            if ($owners.Count -gt 0) {
                Write-Host -ForegroundColor Green "  Owners ($($owners.Count)):"
                foreach ($o in $owners) {
                    Write-Host "    - $($o.displayName)  ($( if ($o.userPrincipalName) { $o.userPrincipalName } else { $o.id } ))"
                }
            }
        } catch { }

        # Directory roles
        if (-not $SkipElevated) {
            try {
                $spRrResp = Invoke-GRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$targetId'&`$expand=roleDefinition" -TS $TS
                $spDroles = @($spRrResp.value)
                if ($spDroles.Count -gt 0) {
                    Write-Host -ForegroundColor Green "  Directory role assignments ($($spDroles.Count)):"
                    foreach ($dr in $spDroles) {
                        $rn = if ($dr.roleDefinition) { $dr.roleDefinition.displayName } else { $dr.roleDefinitionId }
                        $sc = if ($dr.directoryScopeId -eq "/") { "Tenant-wide" } else { $dr.directoryScopeId }
                        Write-Host -ForegroundColor Green "    [+] $rn  scope:$sc"
                        Add-Finding $findings "High" "Roles" "SP has active directory role: $rn" "Scope: $sc"
                    }
                }
            } catch {
                Write-Host -ForegroundColor Yellow "  [*] SP directory roles: $($_.Exception.Message -replace 'HTTP \d+ - ','')"
            }
        }
    }

    # -----------------------------------------------------------------------
    # 12. Access summary & findings
    # -----------------------------------------------------------------------

    Write-Section "12. Access Summary & Findings"

    $bySeverity = @{
        Critical = @($findings | Where-Object { $_.Severity -eq "Critical" })
        High     = @($findings | Where-Object { $_.Severity -eq "High"     })
        Medium   = @($findings | Where-Object { $_.Severity -eq "Medium"   })
        Info     = @($findings | Where-Object { $_.Severity -eq "Info"     })
    }

    foreach ($sev in @("Critical","High","Medium","Info")) {
        $grp = $bySeverity[$sev]
        if ($grp.Count -eq 0) { continue }
        $col = switch ($sev) { "Critical" { "Red" }; "High" { "Red" }; "Medium" { "Yellow" }; default { "Cyan" } }
        $tag = switch ($sev) { "Critical" { "[!!!]" }; "High" { "[!]" }; "Medium" { "[~]" }; default { "[i]" } }
        Write-Host -ForegroundColor $col "  $sev ($($grp.Count)):"
        foreach ($f in $grp) {
            Write-Host -ForegroundColor $col "    $tag [$($f.Category)] $($f.Finding)"
            if ($f.Detail) { Write-Host -ForegroundColor DarkGray "          $($f.Detail)" }
        }
    }

    if ($findings.Count -eq 0) {
        Write-Host -ForegroundColor Green "  No findings flagged."
    }

    if ($OutputPath -and $findings.Count -gt 0) {
        $fCsv = Join-Path $OutputPath "AccessFindings.csv"
        $findings | Export-Csv -Path $fCsv -NoTypeInformation -Encoding UTF8
        Write-Host -ForegroundColor Green "[*] Findings exported to $fCsv"
    }

    Write-Host ""
    Write-Host -ForegroundColor Cyan ("=" * 70)
    Write-Host -ForegroundColor Cyan "  Invoke-AccessCheck complete."
    Write-Host -ForegroundColor Cyan ("=" * 70)
    Write-Host ""
}
