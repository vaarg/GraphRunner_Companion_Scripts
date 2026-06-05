Companion scripts for GraphRunner.

The `Resume-GroupAudit.ps1` scripts is so you can resume addable group enumeration. Especially helpful if ratelimited on a large environment.

# Load both scripts
```PowerShell
. .\GraphRunner\GraphRunner.ps1
. .\Resume-GroupAudit.ps1
```

# Authenticate (as per GraphRunner normal methods)

```PowerShell
Invoke-RefreshGraphTokens -TenantID "contoso.com" -ClientID "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -RefreshToken "0.A..."
```

# Phase 1 - enumerate all groups (fast, no permission checks)

```PowerShell
Get-GraphGroups -Tokens $tokens -OutputFile .\all_groups.csv
```

# Phase 2 - check which ones you can update members of

```PowerShell
Test-GraphGroupMemberAccess -Tokens $tokens -InputCsv .\all_groups.csv -OutputFile .\updatable.csv
```

# Phase 3 - enrich the updatable ones with full details + membership

```PowerShell
Get-MemberAccessGroupDetails -Tokens $tokens -InputFile .\updatable_ids.txt -OutputFile .\updatable_details.csv -MembersOutputFile .\updatable_members.csv
```
