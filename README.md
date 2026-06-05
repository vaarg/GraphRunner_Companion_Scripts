# Resume-GroupAudit.ps1

A PowerShell supplement to [GraphRunner](https://github.com/dafthack/GraphRunner) that provides a resumable, three-phase workflow for auditing which Entra ID groups the current user can add or remove members from.

## Background

GraphRunner's built-in `Get-UpdatableGroups` cmdlet enumerates all groups and checks member-update access in a single pass. In large tenants this hits two problems:

- **401 errors are silently swallowed.** The inner `estimateAccess` catch block only handles 429 (rate limiting). When the access token expires mid-page, every remaining group on that page fails quietly and is never rechecked.
- **No resume capability.** On failure, the only option is to restart from the beginning and re-enumerate all groups from scratch.
- **Output file collision.** Intermediate results are written as `DisplayName:GUID` text but then overwritten by `Export-Csv` at the very end — if the run fails before completing, the CSV is never written.

`Resume-GroupAudit.ps1` splits the work into three independent phases so each can be run, retried, or resumed without affecting the others.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- [GraphRunner](https://github.com/dafthack/GraphRunner) dot-sourced in the same session (provides `Invoke-RefreshGraphTokens`)
- A valid Graph access token obtained via GraphRunner's `Get-GraphTokens` or `Invoke-RefreshGraphTokens`

## Setup

```powershell
# Dot-source GraphRunner first, then this file
. .\GraphRunner\GraphRunner.ps1
. .\Resume-GroupAudit.ps1
```

> **Encoding note:** The file is pure ASCII. If you edit it, save as ASCII or UTF-8 with BOM. Windows PowerShell 5.1 reads files without a BOM as Windows-1252 by default, which silently corrupts multi-byte Unicode characters (em-dashes, smart quotes, etc.) and causes parse errors.

---

## Workflow Overview

```
Phase 1 - Get-GraphGroups
    Enumerate all groups -> all_groups.csv
            |
            v
Phase 2 - Test-GraphGroupMemberAccess
    Check estimateAccess for each group -> updatable.csv + updatable_ids.txt
            |
            v
Phase 3 - Get-MemberAccessGroupDetails
    Fetch full details + membership for updatable groups
    -> updatable_details.csv + updatable_members.csv
```

Phases 2 and 3 are independent. If phase 2 fails partway through, phase 3 can still be run on whatever was found so far using the `_ids.txt` fallback file.

---

## Authentication

Authenticate using GraphRunner before running any phase. The ClientID used here matters — the refresh token is bound to the client it was issued for, and refreshing with a different ClientID returns HTTP 400.

```powershell
# Example using the Azure Portal client
Invoke-RefreshGraphTokens -TenantID "contoso.com" `
    -ClientID "04b07795-8ddb-461a-bbee-02f9e1bf7b46" `
    -RefreshToken "0.A..."
```

All three functions auto-detect the ClientID from the `appid` claim in the access token JWT, so you do not need to pass `-ClientID` explicitly unless you want to override it.

---

## Phase 1 — Get-GraphGroups

Enumerates all Entra ID groups and writes them to a CSV. No permission checks are performed. This is intentionally fast and cheap — it exists so you have a stable, complete group list before running the expensive `estimateAccess` calls in phase 2.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-Tokens` | Yes | | Token object from GraphRunner |
| `-OutputFile` | No | `all_groups.csv` | Path to write the group list CSV |
| `-Keyword` | No | | Filter groups by display name or description (substring match, multiple values OR'd) |
| `-GraphApiEndpoint` | No | Graph v1.0 `/groups` | Override the starting endpoint |

### Output columns

| Column | Description |
|---|---|
| `id` | Group object ID (GUID) |
| `displayName` | Display name |
| `description` | Description |
| `mail` | Mail address (if set) |

### Example

```powershell
# Enumerate all groups
Get-GraphGroups -Tokens $tokens -OutputFile .\all_groups.csv

# Enumerate only groups matching a keyword
Get-GraphGroups -Tokens $tokens -Keyword "admin","finance" -OutputFile .\filtered_groups.csv
```

---

## Phase 2 — Test-GraphGroupMemberAccess

Calls the Graph `estimateAccess` endpoint for each group in the supplied list to determine whether the current user has the `microsoft.directory/groups/members/update` permission. This is the permission required to add or remove members from a group.

Unlike `Get-UpdatableGroups`, this function:
- Takes a pre-built group list as input rather than enumerating from scratch
- Handles HTTP 401 (token expiry) **reactively** — on receiving a 401 it refreshes the token immediately and retries the same group, rather than silently skipping it
- Respects the `Retry-After` header on HTTP 429 responses
- Writes a `_ids.txt` fallback file per-result as it runs, so progress survives a crash

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-Tokens` | Yes | | Token object from GraphRunner |
| `-InputCsv` | One of three | | CSV with an `id` column (e.g. from `Get-GraphGroups`) |
| `-InputFile` | One of three | | Text file: bare GUIDs or `DisplayName:GUID` per line |
| `-GroupIds` | One of three | | String array of GUIDs passed directly |
| `-OutputFile` | No | `updatable_groups_resumed.csv` | CSV for groups where access is allowed |
| `-Skip` | No | `0` | Skip the first N groups (resume by position) |
| `-StartFromId` | No | | Skip all groups before this GUID (resume by ID) |
| `-RefreshInterval` | No | `300` | Seconds between proactive token refreshes |
| `-ClientID` | No | Auto-detected | Override the client ID used for token refresh |

### Output files

| File | Description |
|---|---|
| `<OutputFile>` | CSV written at the end: `id`, `displayName`, `decision` for each updatable group |
| `<OutputFile stem>_ids.txt` | Appended incrementally: `DisplayName:GUID` per updatable group found. This file is written as results come in and survives a crash. Used as input to phase 3. |

### Resuming after failure

When a group exhausts all retries, the console prints:

```
[!] Giving up on 'Group Name' (xxxxxxxx-...) after 3 attempts.
    Resume tip: -StartFromId 'xxxxxxxx-...'
```

Use that GUID with `-StartFromId` on the next run, pointing at the same `all_groups.csv`:

```powershell
Test-GraphGroupMemberAccess -Tokens $tokens `
    -InputCsv .\all_groups.csv `
    -StartFromId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -OutputFile .\updatable_resume.csv
```

Or if you know roughly how many groups were checked, use `-Skip`:

```powershell
Test-GraphGroupMemberAccess -Tokens $tokens -InputCsv .\all_groups.csv -Skip 300 -OutputFile .\updatable_resume.csv
```

### Examples

```powershell
# Check all groups from phase 1
Test-GraphGroupMemberAccess -Tokens $tokens -InputCsv .\all_groups.csv -OutputFile .\updatable.csv

# Check a specific ad-hoc set of groups
Test-GraphGroupMemberAccess -Tokens $tokens -GroupIds @("guid1","guid2") -OutputFile .\updatable_specific.csv

# Resume from a known group ID
Test-GraphGroupMemberAccess -Tokens $tokens `
    -InputCsv .\all_groups.csv `
    -StartFromId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -OutputFile .\updatable_resume.csv
```

---

## Phase 3 — Get-MemberAccessGroupDetails

Enriches the updatable group list produced by phase 2 with full details fetched from Graph, and fetches the current membership of each group. Designed specifically for the `_ids.txt` fallback file written by `Test-GraphGroupMemberAccess`.

Produces two CSV files: a one-row-per-group summary, and a one-row-per-member membership file that joins back to the summary via `groupId`.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-Tokens` | Yes | | Token object from GraphRunner |
| `-InputFile` | Yes | | Path to a `_ids.txt` file from `Test-GraphGroupMemberAccess` |
| `-OutputFile` | No | `updatable_group_details.csv` | Group summary CSV |
| `-MembersOutputFile` | No | `updatable_group_members.csv` | Membership CSV |
| `-ClientID` | No | Auto-detected | Override the client ID used for token refresh |

### Output: group details CSV

| Column | Description |
|---|---|
| `id` | Group object ID |
| `displayName` | Display name |
| `description` | Description |
| `mail` | Mail address |
| `groupType` | `Microsoft 365`, `Security`, `Mail-Enabled Security`, `Distribution`, or `Unknown` |
| `syncStatus` | `Cloud-only` or `Synced (AD)` |
| `isAssignableToRole` | Whether the group can be assigned to an Entra ID role |
| `visibility` | `Public`, `Private`, or empty |
| `createdDateTime` | Group creation timestamp |
| `memberCount` | Number of direct members |

### Output: members CSV

| Column | Description |
|---|---|
| `groupId` | Foreign key to group details CSV |
| `groupDisplayName` | Group display name (denormalised for readability) |
| `memberId` | Member object ID |
| `memberDisplayName` | Member display name |
| `memberUPN` | User principal name (users only; empty for groups, service principals, etc.) |
| `memberMail` | Mail address |
| `memberType` | `User`, `Group`, `ServicePrincipal`, `Device`, etc. (derived from `@odata.type`) |

### Example

```powershell
Get-MemberAccessGroupDetails -Tokens $tokens `
    -InputFile .\updatable_ids.txt `
    -OutputFile .\updatable_details.csv `
    -MembersOutputFile .\updatable_members.csv
```

---

## Full Workflow Example

```powershell
# Load dependencies
. .\GraphRunner\GraphRunner.ps1
. .\Resume-GroupAudit.ps1

# Authenticate
Invoke-RefreshGraphTokens -TenantID "contoso.com" `
    -ClientID "04b07795-8ddb-461a-bbee-02f9e1bf7b46" `
    -RefreshToken "0.A..."

# Phase 1: Enumerate all groups (fast, no permission checks)
Get-GraphGroups -Tokens $tokens -OutputFile .\all_groups.csv

# Phase 2: Check which groups allow member updates
Test-GraphGroupMemberAccess -Tokens $tokens `
    -InputCsv .\all_groups.csv `
    -OutputFile .\updatable.csv

# Phase 3: Enrich updatable groups with details and membership
# The _ids.txt filename mirrors the OutputFile stem from phase 2
Get-MemberAccessGroupDetails -Tokens $tokens `
    -InputFile .\updatable_ids.txt `
    -OutputFile .\updatable_details.csv `
    -MembersOutputFile .\updatable_members.csv
```

### Partial run / resume

```powershell
# If phase 2 failed partway through, resume from the last known group
Test-GraphGroupMemberAccess -Tokens $tokens `
    -InputCsv .\all_groups.csv `
    -StartFromId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -OutputFile .\updatable_resume.csv

# Phase 3 still works on whatever was found — both runs wrote to _ids.txt
# Combine them first if needed, then deduplicate
Get-Content .\updatable_ids.txt, .\updatable_resume_ids.txt | Sort-Object -Unique | Set-Content .\combined_ids.txt

Get-MemberAccessGroupDetails -Tokens $tokens `
    -InputFile .\combined_ids.txt `
    -OutputFile .\updatable_details.csv `
    -MembersOutputFile .\updatable_members.csv
```

---

## Relationship to GraphRunner

This file is a supplement, not a replacement. It depends on GraphRunner being loaded and uses `Invoke-RefreshGraphTokens` from it. The `estimateAccess` logic in `Test-GraphGroupMemberAccess` is functionally identical to `Get-UpdatableGroups` — same endpoint, same request body, same response check — the difference is solely in resilience and structure.

GraphRunner is authored by Beau Bullock ([@dafthack](https://github.com/dafthack)) and licensed under MIT.
