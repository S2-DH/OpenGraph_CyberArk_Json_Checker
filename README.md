# Test-CyberArkHoundJson.ps1

A PowerShell script that validates and analyses **CyberArkHound** OpenGraph JSON files, and explains **why ingesting CyberArk data increases Attack Path findings** in BloodHound Enterprise.

[CyberArkHound](https://github.com/jazofra/CyberArkHound) collects CyberArk PVWA / Privilege Cloud data (users, groups, safes, accounts, platforms, CCP applications, PSM servers) and links it to Active Directory. Those links can create new paths from AD principals, or from CyberArk identities themselves, into AD Tier Zero. When findings jump after an ingest, this script finds the edges, safes and identities responsible, broken down per AD domain.

> For a generic version that works with any OpenGraph collector, see `Test-OpenGraphJson.ps1`.

---

## Contents

- [The problem it solves](#the-problem-it-solves)
- [How CyberArk data reaches AD](#how-cyberark-data-reaches-ad)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Parameters](#parameters)
- [Report sections](#report-sections)
- [Reading the LIKELY CAUSE summary](#reading-the-likely-cause-summary)
- [Output files](#output-files)
- [Typical investigation workflow](#typical-investigation-workflow)
- [Common causes it identifies](#common-causes-it-identifies)
- [Examples](#examples)
- [Limitations](#limitations)
- [References](#references)

---

## The problem it solves

A CyberArkHound ingest that used to be stable suddenly adds a large number of findings in one or more AD domains. Narrowing this down in the tenant is slow. The CyberArk graph can hold tens of thousands of edges, and the path that matters may start from a node with **no inbound edges at all**.

The script works offline on the JSON and answers:

- **Is the file valid?** It checks for anything BloodHound would reject, drop or fail to resolve.
- **Which AD domains does the CyberArk data reach, and how much?**
- **Which edge kind, safe, group or identity creates the paths?**
- **What changed since the last good collection?** (with `-BaselinePath`)

---

## How CyberArk data reaches AD

CyberArkHound adds **hybrid edges** that match AD nodes by name:

| Edge | Direction | Created when |
|---|---|---|
| `CyberArk_SyncsToUser` | AD user → CyberArk user | A CyberArk user is LDAP-synced |
| `CyberArk_SyncsToGroup` | AD group → CyberArk group | A CyberArk group is directory-synced |
| `CyberArk_SyncsToADUser` | CyberArk account → AD user | The account's address matches a domain in the collector's `--target-domains` |
| `CyberArk_CanConnect` | CyberArk account → AD computer | The account's address is a host in a `--target-domains` domain |

Inside CyberArk, traversable edges join the two ends together:
- `MemberOf`
- `HasAccessTo` (safe member → every account in the safe)
- `CanGrantAccessTo`
- `Contains`
- `ManagedBy` (CPM → safe)
- `LinkedTo`
- `CanRetrieveViaCCP`
- `CanHijackViaReconcile`

So a typical path looks like this:

```
AD user/group ─SyncsTo*─▶ CyberArk user/group ─MemberOf / HasAccessTo─▶ CyberArk account ─SyncsToADUser─▶ AD user (Tier Zero)
```

There's a second kind of path that is easy to miss. CyberArk users, groups, accounts and applications are **principal kinds** in the CyberArkHound schema, so BloodHound can treat them as attackers in their own right. A CPM or Credential Provider identity with **no inbound edges** can still produce findings for every Tier Zero account it can retrieve.

---

## Requirements

| | |
|---|---|
| PowerShell | **7.x recommended**. Windows PowerShell 5.1 is supported. |
| OS | Windows, Linux or macOS |
| Modules | None. The analysis engine is inline C# compiled at runtime with `Add-Type`. |
| Memory | The file is read fully into memory. Allow roughly **4–6× the JSON size** in RAM. |
| BloodHound access | Not needed for the script. The generated Cypher is for confirming results in the tenant. |

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Unblock-File .\Test-CyberArkHoundJson.ps1
```

---

## Quick start

```powershell
.\Test-CyberArkHoundJson.ps1 -Path .\cyberark_opengraph.json
```

Read the **LIKELY CAUSE** block at the end of the console output first. The full report, CSVs and Cypher queries are written to `.\CAH-Analysis-<timestamp>\`.

Performance: a 55 MB file with about 300k edges takes around 20 seconds on PowerShell 7.

---

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-Path` | Yes | The CyberArkHound JSON that produces the increase. |
| `-BaselinePath` | No | An older CyberArkHound JSON that ingested **without** the increase. Gives exact attribution of the increase to the new edges. Legacy pre-v2 kind names (`CyberArkHasAccessTo`, `SyncsToCyberArkUser` …) are mapped automatically. |
| `-SchemaPath` | No | CyberArkHound `extension/schema.json`. Without it, the script uses a built-in copy of the **v2.1.0** traversability flags and principal kinds. Supply it if your collector uses a different schema version. |
| `-TierZeroFile` | No | Tier Zero AD object names exported from BloodHound, one per line (e.g. `ADMINISTRATOR@CORP.LOCAL`, `DC01.CORP.LOCAL`), or a CSV with a `name` or `label` column. Only paths ending on these objects are counted, which is much closer to Tier Zero findings. |
| `-OutputFolder` | No | Output location. Default: `.\CAH-Analysis-<yyyyMMdd-HHmmss>`. |
| `-Top` | No | Rows per "top N" table. Default `25`. CSVs contain everything. |
| `-SkipWhatIf` | No | Skips the per-edge-kind removal analysis. Faster on very large files. |

---

## Report sections

| # | Section | What it tells you |
|---|---|---|
| 1 | **Validation** | OpenGraph rule problems and CyberArkHound-specific issues (see below) |
| 2 | **Nodes and edges by kind** | Counts, and the change per kind if a baseline is supplied |
| 3 | **Hybrid (AD-facing) edges by domain** | `SyncsToUser` / `SyncsToGroup` / `SyncsToADUser` / `CanConnect` counts per AD domain |
| 4 | **Bridge paths into AD by target domain** | Per domain: AD targets, AD and CyberArk principals upstream, and entry → target pairs (with deltas vs baseline) |
| 5 | **What-if** | Paths lost when each traversable edge kind is removed, per domain |
| 6 / 7 | **Chokepoint nodes / edges** | Ranked by *AD entries reaching it × AD targets reachable from it* |
| 8 | **Most-reached AD targets / widest AD entry points** | Which AD objects are reached most, and which AD principals reach most |
| 8b | **CyberArk principals with the most AD targets reachable** | Identities that are path *origins*, including those with `InboundTraversableEdges = 0`. **Infra** flags CyberArk infrastructure identities (`PasswordManager*`, `PROV_*`, `PSMApp_*`, `PSMGw_*` …). |
| 8c | **Safes whose members reach AD targets** | Per safe: members (and how many are infrastructure), accounts, AD targets, domains. Often the fastest route to the cause. |
| 9 | **Fan-out checks** | AD groups synced into CyberArk groups (with *broad* groups such as Domain Users flagged), and `CanHijackViaReconcile` edges per safe |
| 10 | **Edges new since baseline** | New edges grouped by kind (with `-BaselinePath`) |
| 11 | **Attribution** | Paths lost when only the **new** edges of each kind are removed: the exact share of the increase per kind and domain (with `-BaselinePath`) |
| — | **LIKELY CAUSE** | The summary: ranked causes, no-inbound infrastructure identities, top safes and members, biggest chokepoints, broad synced groups, and what to check in the tenant |

### Validation checks

**Payload rules**
- `graph` with `nodes` and `edges` arrays, and `metadata.source_kind`
- Duplicate node ids, and nodes without kinds
- Edge kind pattern `^[A-Za-z0-9_]+$`, and the reserved `tag_` prefix
- Post-processed edge kinds included in the payload
- `match_by` endpoint rules
- Property values: nulls, nested objects, array types

**CyberArkHound-specific**
- Node and edge kinds missing from the CyberArkHound schema
- Legacy pre-v2 kind names. Old and new names co-exist in BloodHound unless the old data is deleted.
- Dangling id references, e.g. a `Contains` edge to an account that isn't in the file
- Hybrid edges matched by name with no kind filter

---

## Reading the LIKELY CAUSE summary

**With a baseline**, causes are ranked by their share of the *increase*:

```
Bridge pairs went from 4000 to 4401 (+401). Removing every new edge leaves 4000.
1. CyberArk_CanHijackViaReconcile
   400 AD entry->target pairs depend on it (100% of the increase) via 200 new edges; domains: EMEA.CORP.LOCAL=200, LAB.LOCAL=200
```

**Without a baseline**, newer or derived kinds are listed before structural ones. Structural kinds (`MemberOf`, `HasAccessTo`, `SyncsTo*`) sit on almost every path by design, so a high percentage for them is expected and is not on its own a sign of a problem.

**Paths from CyberArk principals** are listed separately, because they need no AD entry point:

```
Paths starting at CyberArk principals: 4603 principal->AD-target pairs. Edge kinds they depend on:
   CyberArk_ManagedBy: 200 pairs
   No-inbound principal: PROV_APPHOST01 [CyberArk_User] reaches 614 AD targets (CyberArk infrastructure identity - effectively Tier Zero)

Safes producing the most member -> AD target pairs:
   WIN-AAM-APPS: 3 members (3 infra) x 611 AD targets [CORP.LOCAL=611]
      members: PasswordManager; PROV_APPHOST01; PROV_APPHOST02
```

---

## Output files

| File | Contents |
|---|---|
| `Report.txt` | Full console report |
| `validation.csv` | Validation issues |
| `edge_kinds.csv` / `edge_kinds_vs_baseline.csv` | Edge counts per kind (and changes) |
| `hybrid_edges_by_domain.csv` | Hybrid edges per kind and AD domain |
| `domains.csv` / `domains_vs_baseline.csv` | Bridge paths per AD domain (and changes) |
| `whatif_edge_kinds.csv` | Paths lost per edge kind removed, per domain |
| `top_nodes.csv` / `top_edges.csv` | Chokepoint nodes and edges |
| `ad_targets.csv` / `ad_entries.csv` | AD targets and AD entry points with their reach |
| `ca_principals_reach.csv` | CyberArk principals as path origins: reach, inbound edges, infra flag |
| `safes_reach.csv` | Safes ranked by member × AD target pairs, with member names and domains |
| `synced_ad_groups.csv` | AD groups synced into CyberArk groups |
| `reconcile_hijack_by_safe.csv` | `CanHijackViaReconcile` edges per safe |
| `new_edges_vs_baseline.csv` / `attribution_new_edges.csv` | New edges, and their contribution to the increase |
| `cypher_queries.txt` | Cypher to confirm the findings in the tenant |

### Cypher queries

`cypher_queries.txt` includes:
- CyberArk accounts mapped to Tier Zero AD users and computers
- CPM → safe → account → Tier Zero paths
- Reconcile-hijack and CCP retrieval paths
- AD groups synced into CyberArk
- Outbound flows from the top CyberArk principals
- Member → account → Tier Zero paths for the top safes
- Accounts mapped into each top domain
- Inbound and outbound edges of the top chokepoints

Every query returns **whole paths** (`RETURN p`), so they run in the BloodHound Enterprise Cypher editor. Read property values in the entity panel.

Notes:
- Newer tenants mark Tier Zero with the `Tag_Tier_Zero` label. On older tenants, use `COALESCE(n.system_tags,'') CONTAINS 'admin_tier_0'`. Both variants are included where it matters.
- The payload node `id` is stored as `objectid`. The chokepoint queries use it.

Useful hand-written queries:

```cypher
// Everything with access to one safe
MATCH p=(m)-[r:CyberArk_HasAccessTo]->(:CyberArk_Account)
WHERE r.safeName = 'SAFE-NAME'
RETURN p LIMIT 1000
```
```cypher
// Safe members -> accounts -> Tier Zero AD users
MATCH p=(m)-[r:CyberArk_HasAccessTo]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User)
WHERE r.safeName = 'SAFE-NAME' AND u:Tag_Tier_Zero
RETURN p LIMIT 500
```
```cypher
// Short paths from one CyberArk identity to Tier Zero
MATCH p=(cu:CyberArk_User)-[*1..3]->(t:Tag_Tier_Zero)
WHERE cu.name CONTAINS 'IDENTITY-NAME'
RETURN p LIMIT 100
```

---

## Typical investigation workflow

1. **Run the script on the current file.** Fix any validation ERRORs first.
2. **Read LIKELY CAUSE, then sections 8b and 8c.** Most real-world increases come from one safe or one identity.
3. **Narrow to Tier Zero.** Export the Tier Zero names from BloodHound and re-run with `-TierZeroFile`, so only paths that matter for findings are counted.
4. **If you have an older file, re-run with `-BaselinePath`.** Section 11 gives the exact attribution.
5. **Confirm in the tenant** with `cypher_queries.txt`.
6. **Check what can't be seen in the JSON:**
   - the collector's command line, especially `--target-domains`, and its version history
   - when the CyberArkHound schema was installed or upgraded (*Administration → OpenGraph Management*). Without a schema the data is a generic graph; with one, `is_traversable: true` edges feed pathfinding and findings.
   - whether old pre-v2 kinds or old node ids are still in the graph alongside new data

---

## Common causes it identifies

| Cause | How it shows up | Typical remediation |
|---|---|---|
| **A domain added to `--target-domains`** | A large `SyncsToADUser` count appears for one domain. Section 4 shows that domain dominating. | Confirm the change was intended, then review the safes that hold those accounts |
| **CPM / Credential Provider identities** (`PasswordManager`, `PROV_*`) in safes holding Tier Zero accounts | 8b: no-inbound infra principals with large reach. 8c: safe with infra-only members. | Classify CyberArk infrastructure identities (and their hosts) as Tier Zero. Move Tier Zero accounts into dedicated safes. |
| **Broad AD group synced into CyberArk** (e.g. Domain Users) | Section 9 `Broad = True`, with a large `TargetsReachableFromCAGroup` | Sync a scoped group instead |
| **`CanHijackViaReconcile`** (added in CyberArkHound June 2026) | Section 9 per-safe table, plus attribution | Restrict `addAccounts` / `manageSafe` on safes with reconcile-linked platforms |
| **`CanRetrieveViaCCP`** (added in CyberArkHound June 2026) | Attribution / what-if | Restrict AppID authentication and `AllowedSafes` |
| **Schema installed or upgraded** | Little or no change in the JSON, but findings rose | Expected: CyberArk paths now count. Review the top safes and identities. |
| **AD exposure on the mapped accounts** | Tier Zero query results end one hop away (Owns / GenericAll on Sites or OUs, DNSAdmins-type membership) | Remove the excess AD rights, or treat those accounts as Tier Zero |

**Not a cause:** `unable to resolve endpoint: "name" equals_ignore_case "HOST.DOMAIN"` ingest errors usually come from `CyberArk_PSMServerHostedOn`, where a PSM address is a load-balancer or alias rather than an AD computer name. That edge is non-traversable and is dropped when it can't resolve, so it removes data rather than adding paths.

---

## Examples

```powershell
# Basic run
.\Test-CyberArkHoundJson.ps1 -Path .\cyberark_opengraph.json

# Exact attribution against a known-good collection
.\Test-CyberArkHoundJson.ps1 -Path .\cyberark_new.json -BaselinePath .\cyberark_old.json

# Tier Zero only, with the schema shipped with your collector version
.\Test-CyberArkHoundJson.ps1 -Path .\cyberark_new.json -TierZeroFile .\tier0.txt -SchemaPath .\schema.json

# Quick validation and summary on a very large file
.\Test-CyberArkHoundJson.ps1 -Path .\cyberark_big.json -SkipWhatIf -Top 10
```

---

## Limitations

- **Offline only.** The script can't see the tenant. It can't confirm that name-matched AD targets exist, that they are Tier Zero (unless you pass `-TierZeroFile`), or which schema version is installed.
- **Paths stop at the AD boundary.** Reachability ends at the AD node that a CyberArk edge points to. It doesn't follow AD edges further, e.g. an AD user who owns a Tier Zero OU. Use the Cypher queries for that.
- **Path counts indicate drivers; they are not finding counts.** BloodHound Enterprise findings use their own zone and finding logic. Expect the same direction, domains and drivers, not identical numbers.
- **Some analysis treats an AD group as one entry point.** Sections 4–8 don't expand an AD group's AD membership. A synced group with thousands of members has a much larger real exposure than its pair count suggests.
- **The infrastructure identity list is name-based.** The Infra flag matches common CyberArk naming (`PasswordManager*`, `PROV_*`, `PSMApp_*`, `PSMGw_*`, built-in vault users). Custom names won't be flagged.
- **Built-in traversability is CyberArkHound schema v2.1.0.** Use `-SchemaPath` for other versions.

---

## References

- CyberArkHound: <https://github.com/jazofra/CyberArkHound>
- OpenGraph data payloads: <https://bloodhound.specterops.io/opengraph/developer/graph-data>
- OpenGraph edges: <https://bloodhound.specterops.io/opengraph/developer/edges>
- Extension definition schema: <https://bloodhound.specterops.io/opengraph/developer/graph-definition>
- Graph theory background: <https://bloodhound.specterops.io/opengraph/developer/graph-theory>
