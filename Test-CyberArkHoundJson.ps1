<#
.SYNOPSIS
    Validates and analyses a CyberArkHound OpenGraph JSON file to explain an
    increase in BloodHound (Enterprise) Attack Path findings.

.DESCRIPTION
    1. Validates the payload against the OpenGraph data rules (structure,
       source_kind, edge kind pattern, reserved tag_ prefix, endpoint matching
       rules, property types, post-processed edge kinds, dangling id references,
       kinds not defined in the CyberArkHound extension schema).
    2. Summarises nodes / edges by kind, flags traversable and hybrid (AD-facing)
       edges, and breaks hybrid edges down by AD domain.
    3. Builds the traversable graph and counts "bridge paths":
           AD principal --(SyncsToUser/SyncsToGroup)--> CyberArk ... --(SyncsToADUser/CanConnect)--> AD user/computer
       per target domain. These are the paths that land in an AD domain's
       attack-path analysis.
    4. What-if analysis: re-runs the path count with each traversable edge kind
       removed. The kind whose removal makes the most paths disappear is the
       strongest candidate for the findings increase.
    5. Chokepoints: ranks individual nodes and edges by the number of
       (entry, target) pairs that can pass through them.
    6. Optional -BaselinePath: compares against an older (known-good) JSON,
       including legacy pre-v2 kind names (CyberArkHasAccessTo etc.).

    All results are written to console, a Report.txt, CSV files and a
    Cypher query file (queries return whole paths for the BHE Cypher editor).

.PARAMETER Path
    CyberArkHound JSON that produces the findings increase.
.PARAMETER BaselinePath
    Optional older JSON that ingested without the increase.
.PARAMETER SchemaPath
    Optional CyberArkHound extension schema.json (extension/schema.json in the repo)
    to use for traversability instead of the built-in v2.1.0 list.
.PARAMETER TierZeroFile
    Optional list of Tier Zero AD object names exported from BHE (one per line, e.g.
    ADMINISTRATOR@CORP.LOCAL / DC01.CORP.LOCAL, or a CSV with a 'name' column).
    When supplied, only paths ending on these AD objects are counted - this mirrors
    Tier Zero attack-path findings much more closely.
.PARAMETER OutputFolder
    Where to write the report and CSVs. Defaults to .\CAH-Analysis-<timestamp>.
.PARAMETER Top
    Rows to show in "top N" tables. Default 25.
.PARAMETER SkipWhatIf
    Skip the per-edge-kind removal analysis (faster on very large files).

.EXAMPLE
    .\Test-CyberArkHoundJson.ps1 -Path .\cyberark_current.json
.EXAMPLE
    .\Test-CyberArkHoundJson.ps1 -Path .\cyberark_current.json -BaselinePath .\cyberark_old.json -SchemaPath .\schema.json

.NOTES
    PowerShell 7+ recommended (much faster JSON parsing). Windows PowerShell 5.1 works.
    The file is read fully into memory; budget roughly 4-6x the file size in RAM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$BaselinePath,
    [string]$SchemaPath,
    [string]$TierZeroFile,
    [string]$OutputFolder,
    [int]$Top = 25,
    [switch]$SkipWhatIf
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

#region ---------- Reference data ----------
# Traversability from CyberArkHound extension/schema.json v2.1.0
$script:Traversable = @{
    'CyberArk_HasAccessTo' = $true; 'CyberArk_CanGrantAccessTo' = $true; 'CyberArk_CanRetrieveViaCCP' = $true
    'CyberArk_CCPAllowedFrom' = $false; 'CyberArk_CanHijackViaReconcile' = $true; 'CyberArk_CanApprove' = $false
    'CyberArk_MemberOf' = $true; 'CyberArk_InstanceContains' = $false; 'CyberArk_Contains' = $true
    'CyberArk_Created' = $false; 'CyberArk_ManagedBy' = $true; 'CyberArk_UsesPlatform' = $false
    'CyberArk_UsedAccount' = $false; 'CyberArk_LinkedTo' = $true; 'CyberArk_UsesPSMServer' = $false
    'CyberArk_ManagedByPSM' = $false; 'CyberArk_HasConnectionComponent' = $false; 'CyberArk_PSMServerHostedOn' = $false
    'CyberArk_SyncsToUser' = $true; 'CyberArk_SyncsToGroup' = $true; 'CyberArk_SyncsToADUser' = $true
    'CyberArk_CanConnect' = $true
}
$script:SchemaNodeKinds = @('CyberArk_Instance', 'CyberArk_User', 'CyberArk_Group', 'CyberArk_Safe', 'CyberArk_Account',
    'CyberArk_Platform', 'CyberArk_PSMServer', 'CyberArk_ConnectionComponent', 'CyberArk_Application', 'CyberArkBase')
$script:PrincipalKinds = @('CyberArk_User', 'CyberArk_Group', 'CyberArk_Account', 'CyberArk_Application')
$script:SchemaVersion = 'built-in v2.1.0'
# CyberArk infrastructure identities (CPM, Credential Provider, PSM, built-in admins). They are members of many safes by design.
$script:InfraRegex = '^(PROV_|PasswordManager|PSMApp_|PSMGw_|PSMAdminConnect|PSMMaster|Administrator$|Batch$|Master$|Auditor$)'

$script:PostProcessedKinds = @('ADCSESC1', 'ADCSESC3', 'ADCSESC4', 'ADCSESC6a', 'ADCSESC6b', 'ADCSESC9a', 'ADCSESC9b',
    'ADCSESC10a', 'ADCSESC10b', 'ADCSESC13', 'AddMember', 'AdminTo', 'AZAddOwner', 'AZMGAddMember', 'AZMGAddOwner',
    'AZMGAddSecret', 'AZMGGrantAppRoles', 'AZMGGrantRole', 'AZRoleApprover', 'CanPSRemote', 'CanRDP',
    'CoerceAndRelayNTLMToADCS', 'CoerceAndRelayNTLMToLDAP', 'CoerceAndRelayNTLMToLDAPS', 'CoerceAndRelayNTLMToSMB',
    'DCSync', 'EnrollOnBehalfOf', 'EnterpriseCAFor', 'ExecuteDCOM', 'ExtendedByPolicy', 'GoldenCert', 'HasTrustKeys',
    'IssuedSignedBy', 'Owns', 'OwnsLimitedRights', 'ProtectAdminGroups', 'SyncLAPSPassword', 'SyncedToADUser',
    'SyncedToEntraUser', 'TrustedForNTAuth', 'WriteOwner', 'WriteOwnerLimitedRights')

# Why each edge kind can drive AD findings (from the CyberArkHound source)
$script:KindNotes = @{
    'CyberArk_CanHijackViaReconcile' = 'Added Jun 2026 (v2.x). Created for EVERY safe member with addAccounts/manageSafe x EVERY reconcile account linked from an account in that safe. Reconcile accounts are usually highly privileged AD accounts, so this can give whole groups of safe managers a new path to AD Tier Zero.'
    'CyberArk_CanRetrieveViaCCP'     = 'Added Jun 2026 (v2.x). CCP AppID -> account. Unrestricted AppIDs can fan out to every account in AllowedSafes (wildcard = all safes).'
    'CyberArk_SyncsToGroup'          = 'AD group -> CyberArk group (by name). If a broad AD group (Domain Users, etc.) is synced, every AD member becomes upstream of whatever the CyberArk group can reach.'
    'CyberArk_SyncsToUser'           = 'AD user -> CyberArk user (by name). The AD entry point into the CyberArk graph.'
    'CyberArk_SyncsToADUser'         = 'CyberArk account -> AD user (by name SAM@DOMAIN). The bridge back into AD. If the AD user is Tier Zero, every principal upstream of the account gets a Tier Zero path.'
    'CyberArk_CanConnect'            = 'CyberArk account -> AD computer (by name HOST.DOMAIN). Domain controllers or other Tier Zero computers become reachable.'
    'CyberArk_HasAccessTo'           = 'Safe member -> every account in the safe (fan-out = members x accounts).'
    'CyberArk_CanGrantAccessTo'      = 'Safe member with manageSafeMembers -> safe. Combined with Contains, reaches every account in the safe.'
    'CyberArk_Contains'              = 'Safe -> account.'
    'CyberArk_MemberOf'              = 'CyberArk user -> CyberArk group.'
    'CyberArk_ManagedBy'             = 'CPM user -> every safe it manages (traversable). One CPM user can reach every account in every managed safe, and through SyncsToADUser every mapped AD account. It needs no inbound path to be counted.'
    'CyberArk_LinkedTo'              = 'Account -> linked logon/reconcile/additional account. Platform-based type resolution changed in Jul 2026.'
}
#endregion

#region ---------- Graph engine (C#) ----------
if (-not ('CAHoundV3.Engine' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Management.Automation;
namespace CAHoundV3 {
    public class RunResult {
        public long Pairs;
        public int SourcesWithPath;
        public long[] PairsByDomain;
        public long[] SourceFound;
        public long[] Fwd;
        public long[] Bwd;
    }
    public static class Engine {
        static void Csr(int n, int[] a, int[] b, bool[] on, out int[] off, out int[] adj) {
            off = new int[n + 1];
            for (int i = 0; i < a.Length; i++) if (on[i]) off[a[i] + 1]++;
            for (int i = 0; i < n; i++) off[i + 1] += off[i];
            adj = new int[off[n]];
            int[] pos = (int[])off.Clone();
            for (int i = 0; i < a.Length; i++) if (on[i]) adj[pos[a[i]]++] = b[i];
        }
        // BFS from each source over enabled edges; counts reachable targets (targetDomain >= 0).
        public static RunResult Run(int n, int[] from, int[] to, bool[] on, int[] sources,
                                    int[] targetDomain, int domainCount, bool scores) {
            int[] off, adj; Csr(n, from, to, on, out off, out adj);
            RunResult r = new RunResult();
            r.PairsByDomain = new long[domainCount];
            r.SourceFound = new long[sources.Length];
            long[] fwd = scores ? new long[n] : null;
            int[] stamp = new int[n]; int[] q = new int[n];
            for (int si = 0; si < sources.Length; si++) {
                int s = sources[si]; int st = si + 1; int h = 0, t = 0; long found = 0;
                q[t++] = s; stamp[s] = st;
                while (h < t) {
                    int u = q[h++];
                    if (scores) fwd[u]++;
                    if (u != s && targetDomain[u] >= 0) { found++; r.PairsByDomain[targetDomain[u]]++; }
                    for (int k = off[u]; k < off[u + 1]; k++) { int v = adj[k]; if (stamp[v] != st) { stamp[v] = st; q[t++] = v; } }
                }
                r.SourceFound[si] = found; r.Pairs += found; if (found > 0) r.SourcesWithPath++;
            }
            if (scores) {
                r.Fwd = fwd;
                int[] roff, radj; Csr(n, to, from, on, out roff, out radj);
                long[] bwd = new long[n]; Array.Clear(stamp, 0, n); int ti = 0;
                for (int x = 0; x < n; x++) {
                    if (targetDomain[x] < 0) continue;
                    ti++; int h = 0, t = 0; q[t++] = x; stamp[x] = ti;
                    while (h < t) {
                        int u = q[h++]; bwd[u]++;
                        for (int k = roff[u]; k < roff[u + 1]; k++) { int v = radj[k]; if (stamp[v] != ti) { stamp[v] = ti; q[t++] = v; } }
                    }
                }
                r.Bwd = bwd;
            }
            return r;
        }
        // Per target domain: distinct principal nodes and AD entry nodes upstream (reverse reachability).
        public static long[] Upstream(int n, int[] from, int[] to, bool[] on, int[] targetDomain, int domainCount,
                                      bool[] isPrincipal, bool[] isEntry) {
            int[] roff, radj; Csr(n, to, from, on, out roff, out radj);
            long[] res = new long[domainCount * 2];
            int[] stamp = new int[n]; int[] q = new int[n];
            for (int d = 0; d < domainCount; d++) {
                int st = d + 1; int h = 0, t = 0;
                for (int x = 0; x < n; x++) if (targetDomain[x] == d) { stamp[x] = st; q[t++] = x; }
                while (h < t) {
                    int u = q[h++];
                    if (isPrincipal[u]) res[d * 2]++;
                    if (isEntry[u]) res[d * 2 + 1]++;
                    for (int k = roff[u]; k < roff[u + 1]; k++) { int v = radj[k]; if (stamp[v] != st) { stamp[v] = st; q[t++] = v; } }
                }
            }
            return res;
        }
    }

    public class Ingest {
        public List<string> Label = new List<string>();
        public List<string> Key = new List<string>();
        public List<string> KindOf = new List<string>();
        public List<bool> External = new List<bool>();
        public List<bool> Dangling = new List<bool>();
        public List<string> Domain = new List<string>();
        public int Internal;
        public List<int> From = new List<int>(), To = new List<int>(), KindId = new List<int>();
        public List<object> Props = new List<object>();
        public List<string> Kinds = new List<string>();
        Dictionary<string, int> kindIdx = new Dictionary<string, int>(StringComparer.Ordinal);
        Dictionary<string, int> idx = new Dictionary<string, int>(StringComparer.Ordinal);
        Dictionary<string, int> idxCI = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> NodeKindCount = new Dictionary<string, int>(), EdgeKindCount = new Dictionary<string, int>(),
            EdgeKindHybrid = new Dictionary<string, int>(), HybridByKindDomain = new Dictionary<string, int>(),
            DanglingByKind = new Dictionary<string, int>(), UnknownNodeKinds = new Dictionary<string, int>(),
            UnknownEdgeKinds = new Dictionary<string, int>(), BadKind = new Dictionary<string, int>(),
            PostKinds = new Dictionary<string, int>(), PropIssueCount = new Dictionary<string, int>();
        public Dictionary<string, string> DanglingExample = new Dictionary<string, string>(), LegacyKinds = new Dictionary<string, string>(),
            PropIssueEx = new Dictionary<string, string>();
        public HashSet<string> TagKinds = new HashSet<string>();
        public int DupIds, NoKinds, NoIds, CaseOnly, DupEdges, NoKindFilterHybrid, EndpointErr;
        public string DupExample, EndpointErrEx;
        public HashSet<string> Sigs = new HashSet<string>(StringComparer.Ordinal);

        static object U(object o) { PSObject p = o as PSObject; return p != null ? p.BaseObject : o; }
        static object G(object d, string k) { IDictionary dd = U(d) as IDictionary; if (dd == null) return null; return dd.Contains(k) ? U(dd[k]) : null; }
        static string S(object o) { o = U(o); return o == null ? null : Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture); }
        static readonly Regex KindRx = new Regex("^[A-Za-z0-9_]+$");
        static readonly Regex LegacyRx = new Regex("^CyberArk([A-Z][A-Za-z0-9_]*)$");

        public static string Normalize(string k) {
            if (string.IsNullOrEmpty(k)) return k;
            if (k == "SyncsToCyberArkUser") return "CyberArk_SyncsToUser";
            if (k == "SyncsToCyberArkGroup") return "CyberArk_SyncsToGroup";
            if (k == "SyncsToADUser") return "CyberArk_SyncsToADUser";
            if (k == "CyberArkBase") return k;
            Match m = LegacyRx.Match(k);
            return m.Success ? "CyberArk_" + m.Groups[1].Value : k;
        }
        public static string DomainOf(string v) {
            if (string.IsNullOrEmpty(v)) return "(none)";
            int i = v.IndexOf('@'); if (i >= 0) return v.Substring(i + 1).ToUpperInvariant();
            i = v.IndexOf('.'); if (i >= 0) return v.Substring(i + 1).ToUpperInvariant();
            return "(none)";
        }
        static void Inc(Dictionary<string, int> d, string k) { int c; d.TryGetValue(k, out c); d[k] = c + 1; }

        void PropIssue(string sev, string scope, string msg, string owner) {
            string key = sev + "|properties|" + scope + " " + msg;
            int c; if (PropIssueCount.TryGetValue(key, out c)) PropIssueCount[key] = c + 1; else { PropIssueCount[key] = 1; PropIssueEx[key] = owner; }
        }
        void CheckProps(object props, string scope, string owner) {
            if (props == null) return;
            IDictionary d = props as IDictionary;
            if (d == null) { PropIssue("ERROR", scope, "properties is not an object", owner); return; }
            foreach (DictionaryEntry de in d) {
                object v = U(de.Value); string k = Convert.ToString(de.Key);
                if (v == null) { PropIssue("WARN", scope, "property '" + k + "' is null (schema allows string/number/bool/array only)", owner); continue; }
                if (v is IDictionary) { PropIssue("ERROR", scope, "property '" + k + "' is a nested object", owner); continue; }
                if (v is string) continue;
                IEnumerable list = v as IEnumerable;
                if (list != null) {
                    bool obj = false; HashSet<string> types = new HashSet<string>();
                    foreach (object item0 in list) {
                        object item = U(item0);
                        if (item == null) types.Add("null");
                        else if (item is IDictionary || (item is IEnumerable && !(item is string))) obj = true;
                        else if (item is string) types.Add("string");
                        else if (item is bool) types.Add("bool");
                        else types.Add("number");
                    }
                    if (obj) PropIssue("ERROR", scope, "property '" + k + "' is an array of objects/arrays", owner);
                    else if (types.Count > 1) { List<string> t = new List<string>(types); t.Sort(); PropIssue("ERROR", scope, "property '" + k + "' is a mixed-type array (" + string.Join(",", t.ToArray()) + ")", owner); }
                }
            }
        }
        int AddNode(string key, string label, string kind, bool ext, bool dangling, string domain) {
            int i = Label.Count; idx[key] = i; Label.Add(label); Key.Add(key); KindOf.Add(kind); External.Add(ext); Dangling.Add(dangling); Domain.Add(domain);
            return i;
        }
        // returns node index; out flags
        int Resolve(object ep, string propDomain, out bool dangling, out string matchBy, out string err, out bool hasKind) {
            dangling = false; err = null;
            matchBy = S(G(ep, "match_by")); if (string.IsNullOrEmpty(matchBy)) matchBy = "id";
            object val = G(ep, "value"); object pm = G(ep, "property_matchers");
            hasKind = !string.IsNullOrEmpty(S(G(ep, "kind")));
            if (ep == null) { err = "endpoint missing"; }
            else if (matchBy == "property") {
                IEnumerable pmList = pm as IEnumerable; bool any = false;
                if (pmList != null) foreach (object _ in pmList) { any = true; break; }
                if (!any) err = "match_by=property without property_matchers";
                if (val != null) err = "match_by=property with value";
            } else if (matchBy == "id" || matchBy == "name") {
                if (val == null || S(val) == "") err = "match_by=" + matchBy + " without value";
                if (pm != null) err = "match_by=" + matchBy + " with property_matchers";
            } else err = "unknown match_by '" + matchBy + "'";
            string v = S(val) ?? "";
            string key;
            if (matchBy == "id") {
                int hit; if (idx.TryGetValue(v, out hit) && hit < Internal) return hit;
                if (idxCI.ContainsKey(v)) CaseOnly++;
                key = "ID::" + v; dangling = true;
            } else if (matchBy == "property") {
                List<string> parts = new List<string>();
                IEnumerable pmList = pm as IEnumerable;
                if (pmList != null) foreach (object m in pmList) parts.Add(S(G(m, "key")) + "=" + S(G(m, "value")));
                key = "PROP::" + string.Join("&", parts.ToArray());
                if (string.IsNullOrEmpty(propDomain)) foreach (object m in (pmList ?? new object[0])) { string pv = S(G(m, "value")); if (!string.IsNullOrEmpty(pv) && (pv.Contains("@") || pv.Contains("."))) { v = pv; break; } }
            } else key = "NAME::" + v.ToUpperInvariant();
            int ix;
            if (idx.TryGetValue(key, out ix)) return ix;
            string epKind = S(G(ep, "kind"));
            string dom = !string.IsNullOrEmpty(propDomain) ? propDomain.ToUpperInvariant() : DomainOf(v);
            string lbl = key.Substring(key.IndexOf("::") + 2);
            return AddNode(key, lbl, dangling ? "(dangling id)" : (!string.IsNullOrEmpty(epKind) ? "AD:" + epKind : "AD/external"), true, dangling, dom);
        }

        public void Load(object nodes0, object edges0, string[] schemaNodeKinds, string[] schemaEdgeKinds, string[] postKinds) {
            HashSet<string> snk = new HashSet<string>(schemaNodeKinds ?? new string[0]);
            HashSet<string> sek = new HashSet<string>(schemaEdgeKinds ?? new string[0]);
            HashSet<string> ppk = new HashSet<string>(postKinds ?? new string[0]);
            IEnumerable nodes = U(nodes0) as IEnumerable; IEnumerable edges = U(edges0) as IEnumerable;
            if (nodes != null) foreach (object n0 in nodes) {
                object n = U(n0);
                string id = S(G(n, "id"));
                if (string.IsNullOrEmpty(id)) { NoIds++; continue; }
                List<string> kinds = new List<string>();
                IEnumerable kl = G(n, "kinds") as IEnumerable;
                if (kl != null && !(kl is string)) foreach (object k0 in kl) { string k = S(k0); if (k != null) kinds.Add(k); }
                else if (kl is string) kinds.Add((string)kl);
                if (kinds.Count == 0) { NoKinds++; kinds.Add("(no kind)"); }
                string primary = null;
                for (int i = 0; i < kinds.Count; i++) {
                    string nk = Normalize(kinds[i]); if (nk != kinds[i]) LegacyKinds[kinds[i]] = nk; kinds[i] = nk;
                    if (!snk.Contains(nk)) Inc(UnknownNodeKinds, nk);
                    if (primary == null && nk != "CyberArkBase") primary = nk;
                }
                if (primary == null) primary = kinds[0];
                if (idx.ContainsKey(id)) { DupIds++; if (DupExample == null) DupExample = id; continue; }
                object props = G(n, "properties");
                CheckProps(props, "node " + primary, id);
                string nm = S(G(props, "name")); if (string.IsNullOrEmpty(nm)) nm = id;
                if (!idxCI.ContainsKey(id)) idxCI[id] = Label.Count;
                AddNode(id, nm, primary, false, false, null);
                Inc(NodeKindCount, primary);
            }
            Internal = Label.Count;
            HashSet<string> edgeKeys = new HashSet<string>(StringComparer.Ordinal);
            int ei = 0;
            if (edges != null) foreach (object e0 in edges) {
                object e = U(e0); ei++;
                string raw = S(G(e, "kind")) ?? "";
                string k = Normalize(raw);
                if (k != raw) LegacyKinds[raw] = k;
                if (!KindRx.IsMatch(raw)) Inc(BadKind, raw);
                if (raw.StartsWith("tag_", StringComparison.OrdinalIgnoreCase)) TagKinds.Add(raw);
                if (ppk.Contains(raw)) Inc(PostKinds, raw);
                if (!sek.Contains(k)) Inc(UnknownEdgeKinds, k);
                object props = G(e, "properties");
                CheckProps(props, "edge " + raw, "edge #" + ei);
                string pDom = S(G(props, "domain"));
                bool sd, td, sk, tk; string smb, tmb, serr, terr;
                object sep = G(e, "start"), tep = G(e, "end");
                int s = Resolve(sep, pDom, out sd, out smb, out serr, out sk);
                int t = Resolve(tep, pDom, out td, out tmb, out terr, out tk);
                foreach (string er in new string[] { serr, terr }) if (er != null) { EndpointErr++; if (EndpointErrEx == null) EndpointErrEx = "edge #" + ei + " " + raw + ": " + er; }
                if (sd || td) { Inc(DanglingByKind, k); if (!DanglingExample.ContainsKey(k)) DanglingExample[k] = sd ? "start " + Label[s] : "end " + Label[t]; }
                if (smb != "id" || tmb != "id") {
                    Inc(EdgeKindHybrid, k);
                    int ext = tmb != "id" ? t : s;
                    Inc(HybridByKindDomain, k + "|" + Domain[ext]);
                    if ((smb != "id" && !sk) || (tmb != "id" && !tk)) NoKindFilterHybrid++;
                }
                if (!edgeKeys.Add(k + "|" + s + "|" + t)) DupEdges++;
                Inc(EdgeKindCount, k);
                int kid; if (!kindIdx.TryGetValue(k, out kid)) { kid = Kinds.Count; kindIdx[k] = kid; Kinds.Add(k); }
                From.Add(s); To.Add(t); KindId.Add(kid); Props.Add(props);
                Sigs.Add(k + "|" + Key[s] + "|" + Key[t]);
            }
        }
        public bool[] NewMask(HashSet<string> baseline) {
            bool[] r = new bool[From.Count];
            if (baseline == null) return r;
            for (int i = 0; i < r.Length; i++) r[i] = !baseline.Contains(Kinds[KindId[i]] + "|" + Key[From[i]] + "|" + Key[To[i]]);
            return r;
        }
        public string Ctx(int i) {
            List<string> parts = new List<string>();
            foreach (string ck in new string[] { "viaSafe", "safeName", "permissions", "linkType", "domain" }) {
                string cv = S(G(Props[i], ck)); if (!string.IsNullOrEmpty(cv)) parts.Add(ck + "=" + cv);
            }
            return string.Join("; ", parts.ToArray());
        }
        public string PropStr(int i, string k) { return S(G(Props[i], k)); }
    }

    public static class Util {
        // excludeKind: -1 = none, -2 = any kind (with onlyNew); onlyNew null = all edges of excludeKind
        public static bool[] Mask(int[] kindId, bool[] trav, int excludeKind, bool[] onlyNew) {
            bool[] on = new bool[kindId.Length];
            for (int i = 0; i < on.Length; i++) {
                bool drop = (excludeKind == -2 || kindId[i] == excludeKind) && (onlyNew == null || onlyNew[i]);
                if (excludeKind == -1) drop = false;
                on[i] = trav[i] && !drop;
            }
            return on;
        }
        public static int[] TopK(long[] score, int k) {
            List<int> ids = new List<int>();
            for (int i = 0; i < score.Length; i++) if (score[i] > 0) ids.Add(i);
            ids.Sort(delegate (int a, int b) { return score[b].CompareTo(score[a]); });
            if (ids.Count > k) ids.RemoveRange(k, ids.Count - k);
            return ids.ToArray();
        }
        public static long[] EdgeScores(int[] from, int[] to, bool[] on, long[] fwd, long[] bwd) {
            long[] r = new long[from.Length];
            for (int i = 0; i < r.Length; i++) if (on[i]) r[i] = fwd[from[i]] * bwd[to[i]];
            return r;
        }
        public static long[] NodeScores(long[] fwd, long[] bwd, int internalCount) {
            long[] r = new long[fwd.Length];
            for (int i = 0; i < internalCount; i++) r[i] = fwd[i] * bwd[i];
            return r;
        }
    }
}
'@
}
#endregion

#region ---------- Helpers ----------
$script:Report = New-Object 'System.Collections.Generic.List[string]'
function Write-R {
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    $script:Report.Add($Text)
}
function Write-Section([string]$Title) {
    Write-R ''
    Write-R ('=' * 100) 'DarkCyan'
    Write-R " $Title" 'Cyan'
    Write-R ('=' * 100) 'DarkCyan'
}
function Write-Table($Data) {
    if (-not $Data) { Write-R '  (none)' 'DarkGray'; return }
    $s = ($Data | Format-Table -AutoSize | Out-String -Width 400).TrimEnd()
    foreach ($line in ($s -split "`r?`n")) { Write-R $line }
}
function Get-JV($d, [string]$k) {
    # Works for Hashtable (PS 7 -AsHashtable) and Dictionary[string,object] (PS 5.1 JavaScriptSerializer)
    if ($null -eq $d -or $d -isnot [System.Collections.IDictionary]) { return $null }
    foreach ($key in $d.Keys) { if ($key -ceq $k) { return , $d[$key] } }   # unary comma: keep 1-item arrays as arrays
    return $null
}



function Import-OGJson([string]$File) {
    $full = (Resolve-Path -LiteralPath $File).Path
    $len = (Get-Item -LiteralPath $full).Length
    Write-Host ("Loading {0} ({1:N1} MB)..." -f $full, ($len / 1MB)) -ForegroundColor Yellow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = [IO.File]::ReadAllText($full, [Text.Encoding]::UTF8)
    $bom = $false
    if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1); $bom = $true }
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $obj = $raw | ConvertFrom-Json -AsHashtable -Depth 200
    } else {
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue; $ser.RecursionLimit = 200
        $obj = $ser.DeserializeObject($raw)
    }
    $raw = $null; [GC]::Collect()
    Write-Host ("  parsed in {0:N1}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
    [pscustomobject]@{ Path = $full; SizeMB = [math]::Round($len / 1MB, 1); Root = $obj; HadBom = $bom }
}

#endregion

#region ---------- Analysis ----------
function Invoke-CAHAnalysis([string]$File, [string]$Label, [switch]$NoWhatIf, $BaselineSigs, $TierZero) {
    $loaded = Import-OGJson $File
    $root = $loaded.Root
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $propIssues = @{}
    if ($loaded.HadBom) { $issues.Add('INFO|file|File starts with a UTF-8 BOM') }

    $graph = Get-JV $root 'graph'
    $meta = Get-JV $root 'metadata'
    if ($null -eq $graph) { throw "$File has no top-level 'graph' object - not an OpenGraph payload." }
    $nodes = Get-JV $graph 'nodes'; $edges = Get-JV $graph 'edges'
    if ($null -eq $nodes) { $issues.Add('ERROR|structure|graph.nodes missing'); $nodes = @() }
    if ($null -eq $edges) { $issues.Add('ERROR|structure|graph.edges missing'); $edges = @() }
    $sourceKind = Get-JV $meta 'source_kind'
    if (-not $sourceKind) { $issues.Add('WARN|metadata|metadata.source_kind not set - structured-graph findings require a registered source_kind') }

    # ---- parse + validate (C#) ----
    Write-Host '  indexing nodes and edges...' -ForegroundColor DarkGray
    $ing = New-Object CAHoundV3.Ingest
    $ing.Load($nodes, $edges, [string[]]$script:SchemaNodeKinds, [string[]]@($script:Traversable.Keys), [string[]]$script:PostProcessedKinds)
    $nodes = $null; $edges = $null; $root = $null; $loaded.Root = $null; [GC]::Collect()

    if ($ing.NoIds) { $issues.Add("ERROR|node|$($ing.NoIds) node(s) without id") }
    if ($ing.DupIds) { $issues.Add("WARN|node|$($ing.DupIds) duplicate node id(s) - later copies merge/overwrite (e.g. $($ing.DupExample))") }
    if ($ing.NoKinds) { $issues.Add("ERROR|node|$($ing.NoKinds) node(s) without kinds") }
    foreach ($kv in $ing.PropIssueCount.GetEnumerator()) { $issues.Add("$($kv.Key) - $($kv.Value) occurrence(s), e.g. $($ing.PropIssueEx[$kv.Key])") }
    foreach ($kv in $ing.BadKind.GetEnumerator()) { $issues.Add("ERROR|edge kind|'$($kv.Key)' does not match ^[A-Za-z0-9_]+$ ($($kv.Value) edges) - upload rejected") }
    foreach ($tk in $ing.TagKinds) { $issues.Add("ERROR|edge kind|'$tk' uses reserved tag_ prefix - entire upload rejected") }
    foreach ($kv in $ing.PostKinds.GetEnumerator()) { $issues.Add("WARN|edge kind|'$($kv.Key)' is a post-processed kind ($($kv.Value)) - removed and regenerated by BloodHound") }
    foreach ($kv in $ing.UnknownEdgeKinds.GetEnumerator()) { $issues.Add("WARN|schema|edge kind '$($kv.Key)' ($($kv.Value)) not in extension schema ($script:SchemaVersion) - not part of structured graph") }
    foreach ($kv in $ing.UnknownNodeKinds.GetEnumerator()) { $issues.Add("WARN|schema|node kind '$($kv.Key)' ($($kv.Value)) not in extension schema ($script:SchemaVersion)") }
    foreach ($kv in $ing.LegacyKinds.GetEnumerator()) { $issues.Add("WARN|legacy|pre-v2 kind '$($kv.Key)' (current name: $($kv.Value)). Old and new kinds co-exist in BHE unless old data is deleted.") }
    foreach ($kv in $ing.DanglingByKind.GetEnumerator()) { $issues.Add("WARN|dangling|$($kv.Value) $($kv.Key) edge(s) reference an id not defined in this file (e.g. $($ing.DanglingExample[$kv.Key])) - only resolves if that node already exists in BHE") }
    if ($ing.CaseOnly) { $issues.Add("WARN|dangling|$($ing.CaseOnly) id reference(s) only match a node id when ignoring case") }
    if ($ing.EndpointErr) { $issues.Add("ERROR|endpoint|$($ing.EndpointErr) endpoint(s) break match_by rules (e.g. $($ing.EndpointErrEx))") }
    if ($ing.DupEdges) { $issues.Add("INFO|edge|$($ing.DupEdges) duplicate edge(s) with the same kind/start/end (different properties)") }
    if ($ing.NoKindFilterHybrid) { $issues.Add("INFO|hybrid|$($ing.NoKindFilterHybrid) hybrid edge(s) match AD nodes by name with no kind filter - any node with that name matches") }

    $nodeLbl = $ing.Label; $kindOf = $ing.KindOf; $isExternal = $ing.External; $extDomain = $ing.Domain
    $internalCount = $ing.Internal
    $edgeKindCount = @{}; foreach ($kv in $ing.EdgeKindCount.GetEnumerator()) { $edgeKindCount[$kv.Key] = $kv.Value }
    $nodeKindCount = @{}; foreach ($kv in $ing.NodeKindCount.GetEnumerator()) { $nodeKindCount[$kv.Key] = $kv.Value }
    $kindNames = $ing.Kinds.ToArray()
    $kindIdA = $ing.KindId.ToArray()
    $kindTrav = New-Object bool[] $kindNames.Length
    for ($q = 0; $q -lt $kindNames.Length; $q++) { $kindTrav[$q] = [bool]$script:Traversable[$kindNames[$q]] }

    # ---- build engine arrays ----
    $n = $nodeLbl.Count
    $fromA = $ing.From.ToArray(); $toA = $ing.To.ToArray(); $m = $fromA.Length
    $trav = New-Object bool[] $m
    for ($i = 0; $i -lt $m; $i++) { $trav[$i] = $kindTrav[$kindIdA[$i]] }

    $outTrav = New-Object bool[] $n; $inTrav = New-Object bool[] $n
    for ($i = 0; $i -lt $m; $i++) { if ($trav[$i]) { $outTrav[$fromA[$i]] = $true; $inTrav[$toA[$i]] = $true } }

    $domains = New-Object 'System.Collections.Generic.List[string]'; $domIdx = @{}
    $targetDomain = New-Object int[] $n
    $isPrincipal = New-Object bool[] $n; $isEntry = New-Object bool[] $n
    $sources = New-Object 'System.Collections.Generic.List[int]'
    for ($x = 0; $x -lt $n; $x++) {
        $targetDomain[$x] = -1
        if ($isExternal[$x] -and -not $ing.Dangling[$x]) {
            if ($inTrav[$x] -and ($null -eq $TierZero -or $TierZero.Contains($nodeLbl[$x]))) {
                $d = $extDomain[$x]
                if (-not $domIdx.ContainsKey($d)) { $domIdx[$d] = $domains.Count; $domains.Add($d) }
                $targetDomain[$x] = $domIdx[$d]
            }
            if ($outTrav[$x]) { $sources.Add($x); $isEntry[$x] = $true }
        } elseif (-not $isExternal[$x]) {
            $isPrincipal[$x] = $script:PrincipalKinds -contains $kindOf[$x]
        }
    }
    $srcA = $sources.ToArray()
    $dc = [math]::Max(1, $domains.Count)

    Write-Host '  running path analysis...' -ForegroundColor DarkGray
    $base = [CAHoundV3.Engine]::Run($n, $fromA, $toA, $trav, $srcA, $targetDomain, $dc, $true)
    # Second view: paths that START at CyberArk principals (CPM users, CCP apps, vault users...).
    # BHE counts these principals themselves, so they need no inbound AD path to create findings.
    $pSrc = New-Object 'System.Collections.Generic.List[int]'
    for ($x = 0; $x -lt $internalCount; $x++) { if ($isPrincipal[$x]) { $pSrc.Add($x) } }
    $pSrcA = $pSrc.ToArray()
    $baseP = [CAHoundV3.Engine]::Run($n, $fromA, $toA, $trav, $pSrcA, $targetDomain, $dc, $false)
    $inDeg = New-Object int[] $n
    for ($i = 0; $i -lt $m; $i++) { if ($trav[$i]) { $inDeg[$toA[$i]]++ } }
    $principalRows = @(for ($si = 0; $si -lt $pSrcA.Length; $si++) {
        if ($baseP.SourceFound[$si] -gt 0) {
            $x = $pSrcA[$si]
            [pscustomobject]@{ Principal = $nodeLbl[$x]; Kind = $kindOf[$x]; Infra = [bool]($nodeLbl[$x] -match $script:InfraRegex); ADTargetsReachable = $baseP.SourceFound[$si]; InboundTraversableEdges = $inDeg[$x]; ADEntriesReachingIt = $base.Fwd[$x]; Id = $ing.Key[$x] }
        }
    }) | Sort-Object ADTargetsReachable -Descending
    $up = [CAHoundV3.Engine]::Upstream($n, $fromA, $toA, $trav, $targetDomain, $dc, $isPrincipal, $isEntry)

    $tPerDom = New-Object int[] $dc
    foreach ($td in $targetDomain) { if ($td -ge 0) { $tPerDom[$td]++ } }
    $domainRows = for ($d = 0; $d -lt $domains.Count; $d++) {
        $tcount = $tPerDom[$d]
        [pscustomobject]@{
            Domain                 = $domains[$d]
            ADTargets              = $tcount
            ADEntryPrincipalsUp    = $up[$d * 2 + 1]
            CyberArkPrincipalsUp   = $up[$d * 2]
            EntryToTargetPairs     = $base.PairsByDomain[$d]
        }
    }

    $sigs = $ing.Sigs
    $isNew = $ing.NewMask($BaselineSigs)

    # ---- what-if per traversable kind ----
    $whatIf = @()
    if (-not $NoWhatIf) {
        for ($q = 0; $q -lt $kindNames.Length; $q++) {
            if (-not $kindTrav[$q]) { continue }
            $k = $kindNames[$q]
            Write-Host "  what-if: removing $k" -ForegroundColor DarkGray
            $on = [CAHoundV3.Util]::Mask($kindIdA, $trav, $q, $null)
            $r = [CAHoundV3.Engine]::Run($n, $fromA, $toA, $on, $srcA, $targetDomain, $dc, $false)
            $rP = [CAHoundV3.Engine]::Run($n, $fromA, $toA, $on, $pSrcA, $targetDomain, $dc, $false)
            $row = [ordered]@{
                EdgeKind      = $k
                EdgeCount     = $edgeKindCount[$k]
                PairsLost     = $base.Pairs - $r.Pairs
                PctOfAllPairs = $(if ($base.Pairs) { [math]::Round(100 * ($base.Pairs - $r.Pairs) / $base.Pairs, 1) } else { 0 })
                CAPrincipalPairsLost = $baseP.Pairs - $rP.Pairs
            }
            for ($d = 0; $d -lt $domains.Count; $d++) { $row["Lost:$($domains[$d])"] = $base.PairsByDomain[$d] - $r.PairsByDomain[$d] }
            $whatIf += [pscustomobject]$row
        }
        $whatIf = @($whatIf | Sort-Object PairsLost -Descending)
    }

    # ---- attribution of NEW edges (only with a baseline) ----
    $newWhatIf = @(); $pairsWithoutAllNew = $null
    if ($null -ne $BaselineSigs) {
        $on = [CAHoundV3.Util]::Mask($kindIdA, $trav, -2, $isNew)
        $pairsWithoutAllNew = ([CAHoundV3.Engine]::Run($n, $fromA, $toA, $on, $srcA, $targetDomain, $dc, $false)).Pairs
        $newPerKind = New-Object int[] $kindNames.Length
        for ($i = 0; $i -lt $m; $i++) { if ($isNew[$i] -and $trav[$i]) { $newPerKind[$kindIdA[$i]]++ } }
        for ($q = 0; $q -lt $kindNames.Length; $q++) {
            if ($newPerKind[$q] -eq 0) { continue }
            Write-Host "  attribution: removing new $($kindNames[$q]) edges" -ForegroundColor DarkGray
            $on = [CAHoundV3.Util]::Mask($kindIdA, $trav, $q, $isNew)
            $r = [CAHoundV3.Engine]::Run($n, $fromA, $toA, $on, $srcA, $targetDomain, $dc, $false)
            $row = [ordered]@{ EdgeKind = $kindNames[$q]; NewEdges = $newPerKind[$q]; PairsLost = $base.Pairs - $r.Pairs }
            for ($d = 0; $d -lt $domains.Count; $d++) { $row["Lost:$($domains[$d])"] = $base.PairsByDomain[$d] - $r.PairsByDomain[$d] }
            $newWhatIf += [pscustomobject]$row
        }
        $newWhatIf = @($newWhatIf | Sort-Object PairsLost -Descending)
    }

    # ---- chokepoints ----
    $topNodes = foreach ($x in [CAHoundV3.Util]::TopK([CAHoundV3.Util]::NodeScores($base.Fwd, $base.Bwd, $internalCount), [math]::Max($Top, 50))) {
        [pscustomobject]@{ Node = $nodeLbl[$x]; Kind = $kindOf[$x]; Id = $ing.Key[$x]; EntriesReaching = $base.Fwd[$x]; TargetsReachable = $base.Bwd[$x]; PairsThrough = $base.Fwd[$x] * $base.Bwd[$x] }
    }
    $topNodes = @($topNodes)
    $eScore = [CAHoundV3.Util]::EdgeScores($fromA, $toA, $trav, $base.Fwd, $base.Bwd)
    $topEdges = @(foreach ($i in [CAHoundV3.Util]::TopK($eScore, [math]::Max($Top, 100))) {
        [pscustomobject]@{ EdgeKind = $kindNames[$kindIdA[$i]]; Start = $nodeLbl[$fromA[$i]]; End = $nodeLbl[$toA[$i]]; PairsThrough = $eScore[$i]; Context = $ing.Ctx($i) }
    })

    $targetRows = New-Object 'System.Collections.Generic.List[object]'
    for ($x = 0; $x -lt $n; $x++) {
        if ($targetDomain[$x] -ge 0) {
            $c = $base.Fwd[$x]; if ($isEntry[$x]) { $c-- }
            $targetRows.Add([pscustomobject]@{ ADTarget = $nodeLbl[$x]; Domain = $domains[$targetDomain[$x]]; Kind = $kindOf[$x]; ADEntriesWithPath = $c })
        }
    }
    $entryRows = for ($si = 0; $si -lt $srcA.Length; $si++) {
        $x = $srcA[$si]
        [pscustomobject]@{ ADEntry = $nodeLbl[$x]; Domain = $extDomain[$x]; TargetsReached = $base.SourceFound[$si] }
    }

    # ---- fan-out helpers ----
    $hijackBySafe = @{}
    $kHij = [array]::IndexOf($kindNames, 'CyberArk_CanHijackViaReconcile')
    $kSG = [array]::IndexOf($kindNames, 'CyberArk_SyncsToGroup')
    for ($i = 0; $i -lt $m; $i++) {
        if ($kindIdA[$i] -eq $kHij) {
            $sf = $ing.PropStr($i, 'viaSafe'); if (-not $sf) { $sf = '(unknown)' }
            if (-not $hijackBySafe.ContainsKey($sf)) { $hijackBySafe[$sf] = @{ Edges = 0; Principals = @{}; Reconcile = @{} } }
            $hijackBySafe[$sf].Edges++
            $hijackBySafe[$sf].Principals[$fromA[$i]] = 1
            $hijackBySafe[$sf].Reconcile[$toA[$i]] = 1
        }
    }
    $hijackRows = foreach ($kv in $hijackBySafe.GetEnumerator()) {
        [pscustomobject]@{ ViaSafe = $kv.Key; Edges = $kv.Value.Edges; Principals = $kv.Value.Principals.Count; ReconcileAccounts = (($kv.Value.Reconcile.Keys | ForEach-Object { $nodeLbl[$_] }) -join ', ') }
    }
    $broadRegex = '^(DOMAIN USERS|DOMAIN COMPUTERS|AUTHENTICATED USERS|EVERYONE|USERS|DOMAIN GUESTS|ALL[ _-]?USERS|ALL[ _-]?STAFF)@'
    $syncGroups = for ($i = 0; $i -lt $m; $i++) {
        if ($kindIdA[$i] -eq $kSG) {
            $sg = $nodeLbl[$fromA[$i]]
            [pscustomobject]@{ ADGroup = $sg; CyberArkGroup = $nodeLbl[$toA[$i]]; Broad = [bool]($sg -match $broadRegex); TargetsReachableFromCAGroup = $base.Bwd[$toA[$i]] }
        }
    }

    # ---- edge-kind summary ----
    $kindRows = foreach ($k in $edgeKindCount.Keys) {
        [pscustomobject]@{ EdgeKind = $k; Count = $edgeKindCount[$k]; Traversable = $(if ($script:Traversable.ContainsKey($k)) { $script:Traversable[$k] } else { '?' }); Hybrid = $(if ($ing.EdgeKindHybrid.ContainsKey($k)) { $ing.EdgeKindHybrid[$k] } else { 0 }) }
    }
    $hybridRows = foreach ($kv in $ing.HybridByKindDomain.GetEnumerator()) {
        $p = $kv.Key -split '\|', 2
        [pscustomobject]@{ EdgeKind = $p[0]; Domain = $p[1]; Count = $kv.Value }
    }

    # ---- safe-level view: members -> accounts -> AD targets ----
    $kHas = [array]::IndexOf($kindNames, 'CyberArk_HasAccessTo')
    $kSync = [array]::IndexOf($kindNames, 'CyberArk_SyncsToADUser')
    $kConn = [array]::IndexOf($kindNames, 'CyberArk_CanConnect')
    $acctT = @{}
    for ($i = 0; $i -lt $m; $i++) {
        $kq = $kindIdA[$i]
        if (($kq -eq $kSync -or $kq -eq $kConn) -and $targetDomain[$toA[$i]] -ge 0) {
            if (-not $acctT.ContainsKey($fromA[$i])) { $acctT[$fromA[$i]] = New-Object 'System.Collections.Generic.List[int]' }
            $acctT[$fromA[$i]].Add($toA[$i])
        }
    }
    $safes = @{}
    for ($i = 0; $i -lt $m; $i++) {
        if ($kindIdA[$i] -ne $kHas) { continue }
        $sn = $ing.PropStr($i, 'safeName'); if (-not $sn) { $sn = '(unknown)' }
        if (-not $safes.ContainsKey($sn)) { $safes[$sn] = @{ M = @{}; A = @{} } }
        $safes[$sn].M[$fromA[$i]] = 1; $safes[$sn].A[$toA[$i]] = 1
    }
    $safeRows = @(foreach ($kv in $safes.GetEnumerator()) {
        $tg = @{}; foreach ($a in $kv.Value.A.Keys) { if ($acctT.ContainsKey($a)) { foreach ($t in $acctT[$a]) { $tg[$t] = 1 } } }
        if ($tg.Count -eq 0) { continue }
        $dm = @{}; foreach ($t in $tg.Keys) { $dm[$domains[$targetDomain[$t]]] = 1 + [int]$dm[$domains[$targetDomain[$t]]] }
        $mem = @($kv.Value.M.Keys | ForEach-Object { $nodeLbl[$_] })
        $infra = @($mem | Where-Object { $_ -match $script:InfraRegex })
        [pscustomobject]@{
            Safe = $kv.Key; Members = $mem.Count; InfraMembers = $infra.Count; Accounts = $kv.Value.A.Count; ADTargets = $tg.Count
            PrincipalTargetPairs = [long]$mem.Count * $tg.Count
            Domains = (($dm.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')
            MemberNames = ($mem | Sort-Object) -join '; '
        }
    }) | Sort-Object PrincipalTargetPairs -Descending

    [pscustomobject]@{
        SafeRows = @($safeRows)
        Label = $Label; File = $loaded.Path; SizeMB = $loaded.SizeMB; SourceKind = $sourceKind
        NodeCount = $internalCount; ExternalCount = $n - $internalCount; EdgeCount = $m
        Issues = $issues; NodeKinds = $nodeKindCount; EdgeKinds = @($kindRows | Sort-Object Count -Descending)
        Hybrid = @($hybridRows | Sort-Object EdgeKind, Domain)
        Domains = @($domainRows | Sort-Object EntryToTargetPairs -Descending)
        PrincipalRows = $principalRows; PrincipalPairs = $baseP.Pairs
        TotalPairs = $base.Pairs; EntryCount = $srcA.Length; EntriesWithPath = $base.SourcesWithPath
        WhatIf = $whatIf; TopNodes = $topNodes; TopEdges = $topEdges
        Targets = @($targetRows | Sort-Object ADEntriesWithPath -Descending)
        Entries = @($entryRows | Sort-Object TargetsReached -Descending)
        Hijack = @($hijackRows | Sort-Object Edges -Descending)
        SyncGroups = @($syncGroups | Sort-Object TargetsReachableFromCAGroup -Descending)
        Sigs = $sigs; EdgeKindCount = $edgeKindCount; NewWhatIf = $newWhatIf; PairsWithoutAllNew = $pairsWithoutAllNew
        TierZeroTargets = $(if ($null -ne $TierZero) { ($targetDomain | Where-Object { $_ -ge 0 }).Count } else { $null })
    }
}
#endregion

#region ---------- Main ----------
if ($SchemaPath) {
    $sch = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $SchemaPath).Path) | ConvertFrom-Json
    $script:Traversable = @{}
    foreach ($rk in $sch.relationship_kinds) { $script:Traversable[$rk.name] = [bool]$rk.is_traversable }
    $script:SchemaNodeKinds = @($sch.node_kinds | ForEach-Object { $_.name }) + @($sch.environments | ForEach-Object { $_.source_kind })
    $pk = @($sch.environments | ForEach-Object { $_.principal_kinds } | Where-Object { $_ })
    if ($pk) { $script:PrincipalKinds = $pk }
    $script:SchemaVersion = "$($sch.schema.name) $($sch.schema.version)"
}

if (-not $OutputFolder) { $OutputFolder = Join-Path (Get-Location) ("CAH-Analysis-{0:yyyyMMdd-HHmmss}" -f (Get-Date)) }
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$t0 = $null
if ($TierZeroFile) {
    $t0 = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $tzFull = (Resolve-Path -LiteralPath $TierZeroFile).Path
    if ($tzFull -match '\.csv$') {
        $rows = Import-Csv -LiteralPath $tzFull
        $col = @($rows[0].PSObject.Properties.Name | Where-Object { $_ -match '^(name|label)$' })[0]
        if (-not $col) { $col = @($rows[0].PSObject.Properties.Name)[0] }
        foreach ($r in $rows) { if ($r.$col) { [void]$t0.Add($r.$col.Trim()) } }
    } else {
        foreach ($line in [IO.File]::ReadAllLines($tzFull)) { if ($line.Trim()) { [void]$t0.Add($line.Trim()) } }
    }
    Write-Host "Loaded $($t0.Count) Tier Zero names from $tzFull" -ForegroundColor Yellow
}

$old = $null
if ($BaselinePath) { $old = Invoke-CAHAnalysis -File $BaselinePath -Label 'BASELINE' -NoWhatIf -TierZero $t0 }
$cur = Invoke-CAHAnalysis -File $Path -Label 'CURRENT' -NoWhatIf:$SkipWhatIf -BaselineSigs $(if ($old) { $old.Sigs } else { $null }) -TierZero $t0

Write-Section "CyberArkHound OpenGraph analysis  ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
Write-R "File          : $($cur.File) ($($cur.SizeMB) MB)"
if ($old) { Write-R "Baseline      : $($old.File) ($($old.SizeMB) MB)" }
Write-R "source_kind   : $($cur.SourceKind)"
Write-R "Schema used   : $script:SchemaVersion"
Write-R "Nodes         : $($cur.NodeCount) defined in file, $($cur.ExternalCount) external endpoints (AD/other, resolved by BHE at ingest)"
Write-R "Edges         : $($cur.EdgeCount)"
if ($t0) { Write-R "Tier Zero     : filter ON - $($t0.Count) names loaded, $($cur.TierZeroTargets) of them are AD targets in this file" 'Yellow' }
else { Write-R 'Tier Zero     : filter OFF - every AD user/computer the file links to counts as a target (use -TierZeroFile to narrow)' 'DarkGray' }

Write-Section '1. Validation'
$vrows = foreach ($i in $cur.Issues) { $p = $i -split '\|', 3; [pscustomobject]@{ Severity = $p[0]; Check = $p[1]; Detail = $p[2] } }
$vrows = @($vrows | Sort-Object @{ e = { @{ ERROR = 0; WARN = 1; INFO = 2 }[$_.Severity] } }, Check)
if (-not $vrows) { Write-R '  No validation issues found.' 'Green' } else { Write-Table $vrows }
$vrows | Export-Csv (Join-Path $OutputFolder 'validation.csv') -NoTypeInformation

Write-Section '2. Nodes and edges by kind'
if ($old) {
    $legacy = @($old.Issues | Where-Object { $_ -like 'WARN|legacy|*' })
    if ($legacy) { Write-R "Baseline uses $($legacy.Count) pre-v2 kind name(s) (e.g. CyberArkHasAccessTo); they are mapped to current names for this comparison." 'Yellow' }
}
Write-Table ($cur.NodeKinds.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ NodeKind = $_.Key; Count = $_.Value } })
Write-R ''
if ($old) {
    $allK = @($cur.EdgeKindCount.Keys) + @($old.EdgeKindCount.Keys) | Sort-Object -Unique
    $kd = foreach ($k in $allK) {
        $c = [int]$cur.EdgeKindCount[$k]; $b = [int]$old.EdgeKindCount[$k]
        [pscustomobject]@{ EdgeKind = $k; Traversable = $script:Traversable[$k]; Baseline = $b; Current = $c; Delta = $c - $b; Change = $(if ($b) { '{0:+0;-0;0}%' -f (100 * ($c - $b) / $b) } elseif ($c) { 'NEW' } else { '' }) }
    }
    $kd = @($kd | Sort-Object { [math]::Abs($_.Delta) } -Descending)
    Write-Table $kd
    $kd | Export-Csv (Join-Path $OutputFolder 'edge_kinds_vs_baseline.csv') -NoTypeInformation
} else {
    Write-Table $cur.EdgeKinds
}
$cur.EdgeKinds | Export-Csv (Join-Path $OutputFolder 'edge_kinds.csv') -NoTypeInformation

Write-Section '3. Hybrid (AD-facing) edges by domain'
Write-R 'Edges that match AD nodes by name. These are the only way CyberArk data changes AD-domain findings.' 'DarkGray'
Write-Table $cur.Hybrid
$cur.Hybrid | Export-Csv (Join-Path $OutputFolder 'hybrid_edges_by_domain.csv') -NoTypeInformation

Write-Section '4. Bridge paths into AD by target domain'
Write-R "Entry points (AD principals with traversable edges into CyberArk): $($cur.EntryCount), of which $($cur.EntriesWithPath) reach an AD target." 'DarkGray'
Write-R 'ADEntryPrincipalsUp / CyberArkPrincipalsUp = distinct principals upstream of that domain''s AD targets (what BHE exposure counts grow by).' 'DarkGray'
Write-R "Total AD-entry -> AD-target pairs: $($cur.TotalPairs)" 'White'
if ($old) {
    $od = @{}; foreach ($r in $old.Domains) { $od[$r.Domain] = $r }
    $dd = foreach ($r in $cur.Domains) {
        $o = $od[$r.Domain]
        [pscustomobject]@{ Domain = $r.Domain; ADTargets = $r.ADTargets; Targets_Delta = $r.ADTargets - [int]$o.ADTargets
            CAPrincipalsUp = $r.CyberArkPrincipalsUp; CAPrincipals_Delta = $r.CyberArkPrincipalsUp - [long]$o.CyberArkPrincipalsUp
            ADEntryUp = $r.ADEntryPrincipalsUp; ADEntry_Delta = $r.ADEntryPrincipalsUp - [long]$o.ADEntryPrincipalsUp
            Pairs = $r.EntryToTargetPairs; Pairs_Delta = $r.EntryToTargetPairs - [long]$o.EntryToTargetPairs }
    }
    Write-R "Baseline total pairs: $($old.TotalPairs)  ->  current: $($cur.TotalPairs)" 'White'
    Write-Table ($dd | Sort-Object Pairs_Delta -Descending)
    $dd | Export-Csv (Join-Path $OutputFolder 'domains_vs_baseline.csv') -NoTypeInformation
} else {
    Write-Table $cur.Domains
}
$cur.Domains | Export-Csv (Join-Path $OutputFolder 'domains.csv') -NoTypeInformation

if ($cur.WhatIf) {
    Write-Section '5. What-if: paths lost when each traversable edge kind is removed'
    Write-R 'The kind at the top is what the most AD bridge paths depend on. Per-domain columns show where.' 'DarkGray'
    Write-Table ($cur.WhatIf | Select-Object -First $Top)
    $cur.WhatIf | Export-Csv (Join-Path $OutputFolder 'whatif_edge_kinds.csv') -NoTypeInformation
}

Write-Section "6. Top $Top chokepoint nodes (AD entries reaching node x AD targets reachable from node)"
Write-Table ($cur.TopNodes | Select-Object -First $Top Node, Kind, EntriesReaching, TargetsReachable, PairsThrough)
$cur.TopNodes | Select-Object Node, Kind, Id, EntriesReaching, TargetsReachable, PairsThrough | Export-Csv (Join-Path $OutputFolder 'top_nodes.csv') -NoTypeInformation

Write-Section "7. Top $Top chokepoint edges"
Write-Table ($cur.TopEdges | Select-Object -First $Top)
$cur.TopEdges | Export-Csv (Join-Path $OutputFolder 'top_edges.csv') -NoTypeInformation

Write-Section "8. Most-reached AD targets / widest AD entry points"
Write-Table ($cur.Targets | Select-Object -First $Top)
Write-R ''
Write-Table ($cur.Entries | Select-Object -First $Top)
$cur.Targets | Export-Csv (Join-Path $OutputFolder 'ad_targets.csv') -NoTypeInformation
$cur.Entries | Export-Csv (Join-Path $OutputFolder 'ad_entries.csv') -NoTypeInformation

Write-Section "8b. CyberArk principals with the most AD targets reachable (path origin, no AD entry needed)"
Write-R 'BHE treats these CyberArk principals as attackers in their own right. A principal with InboundTraversableEdges = 0' 'DarkGray'
Write-R 'has no inbound path but still produces findings for every Tier Zero target it reaches (e.g. CPM users via ManagedBy).' 'DarkGray'
Write-R "Total CyberArk-principal -> AD-target pairs: $($cur.PrincipalPairs)" 'White'
Write-Table ($cur.PrincipalRows | Select-Object -First $Top Principal, Kind, Infra, ADTargetsReachable, InboundTraversableEdges, ADEntriesReachingIt)
$cur.PrincipalRows | Export-Csv (Join-Path $OutputFolder 'ca_principals_reach.csv') -NoTypeInformation

Write-Section "8c. Safes whose members reach AD targets (members x AD targets)"
Write-R 'Every member with retrieve/use rights gets HasAccessTo on every account in the safe. InfraMembers = CPM / Provider / PSM identities.' 'DarkGray'
Write-Table ($cur.SafeRows | Select-Object -First $Top Safe, Members, InfraMembers, Accounts, ADTargets, PrincipalTargetPairs, Domains)
$cur.SafeRows | Export-Csv (Join-Path $OutputFolder 'safes_reach.csv') -NoTypeInformation

Write-Section '9. Fan-out checks'
Write-R 'AD groups synced into CyberArk groups (Broad = well-known large group):' 'DarkGray'
Write-Table ($cur.SyncGroups | Select-Object -First $Top)
$cur.SyncGroups | Export-Csv (Join-Path $OutputFolder 'synced_ad_groups.csv') -NoTypeInformation
Write-R ''
Write-R 'CyberArk_CanHijackViaReconcile by safe:' 'DarkGray'
Write-Table ($cur.Hijack | Select-Object -First $Top)
$cur.Hijack | Export-Csv (Join-Path $OutputFolder 'reconcile_hijack_by_safe.csv') -NoTypeInformation

if ($old) {
    Write-Section '10. Edges new since baseline'
    $new = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $cur.Sigs) { if (-not $old.Sigs.Contains($s)) { $p = $s -split '\|', 3; $new.Add([pscustomobject]@{ EdgeKind = $p[0]; Start = ($p[1] -replace '^(ID|NAME|PROP)::', ''); End = ($p[2] -replace '^(ID|NAME|PROP)::', '') }) } }
    $gone = 0; foreach ($s in $old.Sigs) { if (-not $cur.Sigs.Contains($s)) { $gone++ } }
    Write-R "New edges: $($new.Count)   Removed edges: $gone" 'White'
    if ($new.Count -gt 0 -and $gone -gt 0 -and $new.Count -gt 0.8 * $cur.EdgeCount) { Write-R 'Nearly every edge differs - node ids or kind names probably changed between versions (e.g. PVWA tag). Compare counts, not signatures.' 'Yellow' }
    Write-Table ($new | Group-Object EdgeKind | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ EdgeKind = $_.Name; NewEdges = $_.Count } })
    $new | Export-Csv (Join-Path $OutputFolder 'new_edges_vs_baseline.csv') -NoTypeInformation
}

if ($old) {
    Write-Section '11. Attribution: which NEW edges create the increase'
    Write-R 'Removes only the edges that are new since the baseline, one kind at a time, and counts the paths that disappear.' 'DarkGray'
    Write-R ("Current pairs: {0}   current without ANY new edge: {1}   baseline: {2}" -f $cur.TotalPairs, $cur.PairsWithoutAllNew, $old.TotalPairs) 'White'
    if ($cur.NewWhatIf) { Write-Table ($cur.NewWhatIf | Select-Object -First $Top) } else { Write-R '  No new traversable edges.' 'DarkGray' }
    $cur.NewWhatIf | Export-Csv (Join-Path $OutputFolder 'attribution_new_edges.csv') -NoTypeInformation
}

# ---------- Verdict ----------
Write-Section 'LIKELY CAUSE'
$structural = 'CyberArk_MemberOf', 'CyberArk_Contains', 'CyberArk_HasAccessTo', 'CyberArk_SyncsToUser', 'CyberArk_SyncsToGroup', 'CyberArk_SyncsToADUser'
$printKind = {
    param($rank, $kind, $lost, $extra, $color)
    Write-R ("{0}. {1}" -f $rank, $kind) $color
    Write-R ("   {0} AD entry->target pairs depend on it{1}" -f $lost, $extra)
    $kn = $kind -replace " \[structural\]$", ""
    if ($script:KindNotes[$kn]) { Write-R "   $($script:KindNotes[$kn])" "DarkGray" }
}
$anything = $false
if ($old -and $cur.NewWhatIf) {
    $inc = $cur.TotalPairs - $old.TotalPairs
    Write-R ("Bridge pairs went from {0} to {1} ({2:+#;-#;0}). Removing every new edge leaves {3}." -f $old.TotalPairs, $cur.TotalPairs, $inc, $cur.PairsWithoutAllNew) 'White'
    $rank = 1
    foreach ($w in ($cur.NewWhatIf | Where-Object { $_.PairsLost -gt 0 } | Select-Object -First 5)) {
        $pct = if ($inc -gt 0) { ' ({0:N0}% of the increase)' -f [math]::Min(100, 100 * $w.PairsLost / $inc) } else { '' }
        $doms = @($w.PSObject.Properties | Where-Object { $_.Name -like 'Lost:*' -and $_.Value -gt 0 } | Sort-Object Value -Descending | ForEach-Object { "$($_.Name.Substring(5))=$($_.Value)" })
        & $printKind $rank $w.EdgeKind $w.PairsLost ("$pct via $($w.NewEdges) new edges; domains: " + ($doms -join ', ')) 'Yellow'
        $rank++; $anything = $true
    }
} elseif ($cur.WhatIf) {
    Write-R 'No baseline supplied: ranking derived/newer edge kinds first. Structural kinds (MemberOf, HasAccessTo, SyncsTo*) sit on' 'DarkGray'
    Write-R 'almost every path by design, so a high number for them is expected. Re-run with -BaselinePath for exact attribution.' 'DarkGray'
    $rank = 1
    $ordered = @($cur.WhatIf | Where-Object { $_.PairsLost -gt 0 -and $structural -notcontains $_.EdgeKind }) + @($cur.WhatIf | Where-Object { $_.PairsLost -gt 0 -and $structural -contains $_.EdgeKind })
    foreach ($w in ($ordered | Select-Object -First 6)) {
        $isS = $structural -contains $w.EdgeKind
        $doms = @($w.PSObject.Properties | Where-Object { $_.Name -like 'Lost:*' -and $_.Value -gt 0 } | Sort-Object Value -Descending | Select-Object -First 4 | ForEach-Object { "$($_.Name.Substring(5))=$($_.Value)" })
        & $printKind $rank ($w.EdgeKind + $(if ($isS) { ' [structural]' } else { '' })) $w.PairsLost (" ({0}% of all); domains: {1}" -f $w.PctOfAllPairs, ($doms -join ', ')) $(if ($isS) { 'Gray' } else { 'Yellow' })
        $rank++; $anything = $true
    }
}
if ($cur.WhatIf -and $cur.PrincipalPairs -gt 0) {
    Write-R ''
    Write-R ("Paths starting at CyberArk principals: {0} principal->AD-target pairs. Edge kinds they depend on:" -f $cur.PrincipalPairs) 'White'
    foreach ($w in ($cur.WhatIf | Where-Object { $_.CAPrincipalPairsLost -gt 0 -and $structural -notcontains $_.EdgeKind } | Sort-Object CAPrincipalPairsLost -Descending | Select-Object -First 4)) {
        Write-R ("   {0}: {1} pairs" -f $w.EdgeKind, $w.CAPrincipalPairsLost) 'Yellow'
        if ($script:KindNotes[$w.EdgeKind]) { Write-R "      $($script:KindNotes[$w.EdgeKind])" 'DarkGray' }
    }
    foreach ($pr in ($cur.PrincipalRows | Where-Object { $_.InboundTraversableEdges -eq 0 } | Sort-Object @{ e = { -[int]$_.Infra } }, @{ e = { -$_.ADTargetsReachable } } | Select-Object -First 5)) {
        $it = if ($pr.Infra) { ' (CyberArk infrastructure identity - effectively Tier Zero)' } else { '' }
        Write-R ("   No-inbound principal: {0} [{1}] reaches {2} AD targets{3}" -f $pr.Principal, $pr.Kind, $pr.ADTargetsReachable, $it) 'Yellow'
    }
    $topSafes = @($cur.SafeRows | Select-Object -First 3)
    if ($topSafes) {
        Write-R ''
        Write-R 'Safes producing the most member -> AD target pairs:' 'White'
        foreach ($sr in $topSafes) {
            Write-R ("   {0}: {1} members ({2} infra) x {3} AD targets [{4}]" -f $sr.Safe, $sr.Members, $sr.InfraMembers, $sr.ADTargets, $sr.Domains) 'Yellow'
            Write-R ("      members: {0}" -f $sr.MemberNames) 'DarkGray'
        }
    }
    $anything = $true
}
if (-not $anything) {
    Write-R 'No AD bridge paths depend on any edge kind (no traversable path from an AD principal to an AD target).' 'Yellow'
    Write-R 'If findings still rose, see the "not visible in the JSON" checks below.' 'Yellow'
} else {
    $topN = $cur.TopNodes | Select-Object -First 3
    if ($topN) {
        Write-R ''
        Write-R 'Biggest single chokepoints (most entry x target pairs pass through these):' 'White'
        foreach ($t in $topN) { Write-R ("   {0} [{1}] - {2} entries x {3} targets" -f $t.Node, $t.Kind, $t.EntriesReaching, $t.TargetsReachable) }
    }
    $broad = @($cur.SyncGroups | Where-Object Broad)
    if ($broad) { Write-R ''; Write-R ("Broad AD groups synced into CyberArk: {0}" -f (($broad | ForEach-Object ADGroup) -join ', ')) 'Yellow' }
}
Write-R ''
Write-R 'Not visible in the JSON - also check in BHE:' 'White'
Write-R '  - Administration > OpenGraph Management: was the CyberArkHound schema installed or upgraded recently? Without a schema' 'DarkGray'
Write-R '    the data is a generic graph; with it, is_traversable=true edges feed pathfinding and findings.' 'DarkGray'
Write-R '  - Whether the targeted AD users/computers are Tier Zero (use cypher_queries.txt).' 'DarkGray'
Write-R '  - Whether old pre-v2 kinds (CyberArkHasAccessTo...) or old node ids are still in the graph alongside the new data.' 'DarkGray'

# ---------- Cypher ----------
$cy = New-Object 'System.Collections.Generic.List[string]'
$cy.Add('// CyberArkHound triage queries for the BHE Cypher editor. All queries return paths.')
$cy.Add('// Tier Zero filter: newer BHE uses the Tag_Tier_Zero label; older tenants use system_tags. Use whichever your tenant accepts.')
$cy.Add('')
$cy.Add('// 1. CyberArk accounts mapped to Tier Zero AD users')
$cy.Add('MATCH p=(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User) WHERE u:Tag_Tier_Zero RETURN p LIMIT 500')
$cy.Add("MATCH p=(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User) WHERE COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0' RETURN p LIMIT 500")
$cy.Add('')
$cy.Add('// 2. CyberArk accounts that can connect to Tier Zero computers')
$cy.Add('MATCH p=(:CyberArk_Account)-[:CyberArk_CanConnect]->(c:Computer) WHERE c:Tag_Tier_Zero RETURN p LIMIT 500')
$cy.Add('')
$cy.Add('// 3. Reconcile hijack edges that land on AD users')
$cy.Add('MATCH p=()-[:CyberArk_CanHijackViaReconcile]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(:User) RETURN p LIMIT 500')
$cy.Add('')
$cy.Add('// 3b. CPM users -> managed safes -> accounts -> Tier Zero AD users')
$cy.Add('MATCH p=(:CyberArk_User)-[:CyberArk_ManagedBy]->(:CyberArk_Safe)-[:CyberArk_Contains]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User) WHERE u:Tag_Tier_Zero RETURN p LIMIT 500')
foreach ($pr in ($cur.PrincipalRows | Select-Object -First 5)) {
    $sid = $pr.Id -replace "'", "\'"
    $cy.Add("// 3c. Outbound flow from $($pr.Principal) ($($pr.ADTargetsReachable) AD targets)")
    $cy.Add("MATCH p=(n)-[:CyberArk_ManagedBy|CyberArk_CanGrantAccessTo|CyberArk_HasAccessTo|CyberArk_MemberOf|CyberArk_Contains|CyberArk_LinkedTo|CyberArk_CanRetrieveViaCCP*1..3]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser|CyberArk_CanConnect]->(t:Base) WHERE n.objectid = '$sid' RETURN p LIMIT 300")
}
$cy.Add('')
foreach ($sr in ($cur.SafeRows | Where-Object { $_.Safe -ne '(unknown)' } | Select-Object -First 5)) {
    $sn = $sr.Safe -replace "'", "\'"
    $cy.Add("// 3d. Safe $($sr.Safe): members -> accounts -> Tier Zero AD users")
    $cy.Add("MATCH p=(m)-[r:CyberArk_HasAccessTo]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User) WHERE r.safeName = '$sn' AND u:Tag_Tier_Zero RETURN p LIMIT 500")
    $cy.Add("MATCH p=(m)-[r:CyberArk_HasAccessTo]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(:User)-[]->(t:Tag_Tier_Zero) WHERE r.safeName = '$sn' RETURN p LIMIT 500")
}
$cy.Add('')
$cy.Add('// 4. AD groups synced into CyberArk groups')
$cy.Add('MATCH p=(:Group)-[:CyberArk_SyncsToGroup]->(:CyberArk_Group) RETURN p LIMIT 500')
$cy.Add('')
$cy.Add('// 5. CCP retrieval paths to accounts mapped to AD users')
$cy.Add('MATCH p=(:CyberArk_Application)-[:CyberArk_CanRetrieveViaCCP]->(:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(:User) RETURN p LIMIT 500')
foreach ($d in ($cur.Domains | Select-Object -First 5)) {
    $cy.Add('')
    $cy.Add("// 6. Domain $($d.Domain): CyberArk accounts mapped into this domain")
    $cy.Add("MATCH p=(:CyberArk_Account)-[:CyberArk_SyncsToADUser|CyberArk_CanConnect]->(t:Base) WHERE t.domain = '$($d.Domain)' RETURN p LIMIT 500")
}
foreach ($t in ($cur.TopNodes | Select-Object -First 5)) {
    if (-not $t.Id) { continue }
    $sid = $t.Id -replace "'", "\'"
    $cy.Add('')
    $cy.Add("// 7. Chokepoint $($t.Node): inbound and outbound edges")
    $cy.Add("MATCH p=()-[]->(n) WHERE n.objectid = '$sid' RETURN p LIMIT 300")
    $cy.Add("MATCH p=(n)-[]->() WHERE n.objectid = '$sid' RETURN p LIMIT 300")
}
$cy | Set-Content -Path (Join-Path $OutputFolder 'cypher_queries.txt') -Encoding UTF8

$script:Report | Set-Content -Path (Join-Path $OutputFolder 'Report.txt') -Encoding UTF8
Write-Host ''
Write-Host "Report, CSVs and Cypher queries written to: $OutputFolder" -ForegroundColor Green
#endregion
