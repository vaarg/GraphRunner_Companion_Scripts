# GraphSpeeder

PowerShell supplements to [GraphRunner](https://github.com/dafthack/GraphRunner) that add resumability, token-refresh resilience, and scoped enumeration for large or restricted tenants.

## Scripts

### [Resume-GroupAudit.ps1](Resume-GroupAudit.ps1)
Three-phase replacement for `Get-UpdatableGroups`. Splits group enumeration, access checking, and detail enrichment into independent resumable phases. Handles token expiry reactively instead of silently swallowing 401s.

> Full documentation: [wiki/GroupAudit](https://github.com/vaarg/GraphSpeeder/wiki/GroupAudit)

### [Resume-SharePointAudit.ps1](Resume-SharePointAudit.ps1)
Three-phase SharePoint and OneDrive audit. Enumerates site collections via the SPO SDK (admin), tests per-site Graph API access as a standard user, then searches accessible sites directly via `contentSources` — bypassing the site-discovery step that fails in restricted tenants.

> Full documentation: [wiki/SharePointAudit](https://github.com/vaarg/GraphSpeeder/wiki/SharePointAudit)

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- [GraphRunner](https://github.com/dafthack/GraphRunner) dot-sourced in the same session
- A valid Graph access token from GraphRunner's `Get-GraphTokens` or `Invoke-RefreshGraphTokens`

## Setup

```powershell
. .\GraphRunner\GraphRunner.ps1
. .\Resume-GroupAudit.ps1
. .\Resume-SharePointAudit.ps1
```

## Credits

GraphRunner is authored by Beau Bullock ([@dafthack](https://github.com/dafthack)) and licensed under MIT.
