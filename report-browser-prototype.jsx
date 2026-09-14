import React, { useState, useMemo } from "react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, ReferenceLine, Legend,
} from "recharts";

/* ============================================================
   TOKENS  (VM-UI §8.2)
   ============================================================ */
const T = {
  ground: "#FAFBFC",
  surface: "#FFFFFF",
  rule: "#E3E7EB",
  ruleSoft: "#EEF1F4",
  ink: "#1A2027",
  quiet: "#5A6672",
  faint: "#8A94A0",
  accent: "#2E5A8C",
  accentSoft: "#EAF0F7",
  p0: "#8C2E3C",
  p1: "#B5642A",
  p2: "#7A6A2E",
  p3: "#5A6672",
};
const SANS = "'IBM Plex Sans', ui-sans-serif, system-ui, sans-serif";
const MONO = "'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, monospace";

const PRI_COLOR = { P0: T.p0, P1: T.p1, P2: T.p2, P3: T.p3 };
const PRI_FILL = { P0: "#F4E7E9", P1: "#F8EDE3", P2: "#F3F1E4", P3: "#EEF0F2" };

/* ============================================================
   SIMULATED DATA
   ============================================================ */
const REPOS = [
  { name: "wanaware-api", tier: 1, lang: "go", topology: "single", tests: true, owners: ["@jeff", "@waleed"] },
  { name: "wanaware-common", tier: 1, lang: "go", topology: "single", tests: true, owners: ["@suparna"], firstParty: "github.com/org/common" },
  { name: "wanaware-worker", tier: 1, lang: "go", topology: "workspace", tests: true, owners: ["@waleed"] },
  { name: "ldu-sync", tier: 2, lang: "go", topology: "single", tests: true, owners: ["@ashley"] },
  { name: "payments-web", tier: 2, lang: "javascript", topology: "single", tests: false, owners: ["@abdullah"] },
  { name: "ops-tools", tier: 3, lang: "go", topology: "multi", tests: true, owners: ["@suparna"] },
];

const RUNS = [
  { id: "S-001240", n: 1240, kind: "sweep", label: "15 Jul", time: "15 Jul 2026 03:00 UTC", found: 268, fixed: 121, notFixed: 147, scanner: "sha256:41bd", repos: 39, failed: 0 },
  { id: "S-001241", n: 1241, kind: "sweep", label: "22 Jul", time: "22 Jul 2026 03:00 UTC", found: 274, fixed: 138, notFixed: 136, scanner: "sha256:41bd", repos: 40, failed: 0 },
  { id: "S-001242", n: 1242, kind: "sweep", label: "29 Jul", time: "29 Jul 2026 03:00 UTC", found: 281, fixed: 149, notFixed: 132, scanner: "sha256:41bd", repos: 40, failed: 1 },
  { id: "A-000031", n: 31, kind: "advisory", label: "31 Jul", time: "31 Jul 2026 14:22 UTC", found: 12, fixed: 0, notFixed: 12, scanner: "sha256:41bd", repos: 6, failed: 0, advisory: "GHSA-2210-xxq4" },
  { id: "S-001243", n: 1243, kind: "sweep", label: "5 Aug", time: "5 Aug 2026 03:00 UTC", found: 331, fixed: 152, notFixed: 179, scanner: "sha256:7e02", repos: 41, failed: 0, scannerChanged: true },
  { id: "S-001244", n: 1244, kind: "sweep", label: "12 Aug", time: "12 Aug 2026 03:00 UTC", found: 322, fixed: 161, notFixed: 161, scanner: "sha256:7e02", repos: 41, failed: 0 },
  { id: "S-001245", n: 1245, kind: "sweep", label: "19 Aug", time: "19 Aug 2026 03:00 UTC", found: 310, fixed: 170, notFixed: 140, scanner: "sha256:7e02", repos: 41, failed: 0 },
  { id: "S-001246", n: 1246, kind: "sweep", label: "26 Aug", time: "26 Aug 2026 03:00 UTC", found: 298, fixed: 164, notFixed: 134, scanner: "sha256:9c1a", repos: 41, failed: 0, scannerChanged: true },
  { id: "M-000008", n: 8, kind: "manual", label: "28 Aug", time: "28 Aug 2026 09:41 UTC", found: 47, fixed: 6, notFixed: 41, scanner: "sha256:9c1a", repos: 1, failed: 0, actor: "@suparna" },
  { id: "S-001247", n: 1247, kind: "sweep", label: "2 Sep", time: "2 Sep 2026 03:00 UTC", found: 312, fixed: 187, notFixed: 125, scanner: "sha256:9c1a", repos: 41, failed: 2, current: true },
];

const KIND_LABEL = { sweep: "Scheduled sweep", advisory: "Advisory rescan", manual: "Manual run", rescan: "Rescan" };
const KIND_TINT = { sweep: "#EEF1F4", advisory: "#F8EDE3", manual: "#EAF0F7", rescan: "#EEF1F4" };
const KIND_INK = { sweep: "#5A6672", advisory: "#B5642A", manual: "#2E5A8C", rescan: "#5A6672" };

// RUNS includes non-sweep kinds; trends and deltas compare like with like.
const SWEEPS = RUNS.filter((r) => r.kind === "sweep");

function RunId({ r, size = 13 }) {
  return (
    <span className="inline-flex items-center" style={{ gap: 7 }}>
      <span style={{
        fontFamily: MONO, fontSize: size, fontWeight: 600, color: KIND_INK[r.kind],
        background: KIND_TINT[r.kind], padding: "1px 6px", borderRadius: 3,
      }}>{r.id}</span>
      <span style={{ fontSize: size - 1, color: "#5A6672" }}>{r.time}</span>
    </span>
  );
}

const mk = (o) => ({
  transitive: false, kev: false, epss: 0.001, depClass: "production",
  tools: ["osv-scanner"], aliases: [], seenRuns: 3, ...o,
});

const FINDINGS = [
  mk({ fp: "a3f9c21e8b7d4056", id: "GO-2025-3106", aliases: ["CVE-2025-22869", "GHSA-hcg3-q754-cr77"],
    repo: "wanaware-api", category: "dependency", component: "golang.org/x/crypto", major: "v0",
    cur: "v0.35.0", fix: "v0.36.0", pri: "P0", sev: "HIGH", cvss: 7.5, epss: 0.0042, kev: true,
    reach: "true", transitive: true, state: "PR_OPEN", firstSeen: "17 Aug", lastSeen: "2 Sep",
    pr: "#1180", ticket: "#412", tools: ["govulncheck", "osv-scanner"], new: false,
    impact: "Remote attacker can exhaust server memory during SSH key exchange, causing denial of service on the ingress path.",
    via: "wanaware-common → golang.org/x/crypto" }),
  mk({ fp: "b71c04ea99d3f218", id: "CVE-2025-2210", aliases: ["GHSA-2210-xxq4"],
    repo: "wanaware-api", category: "dependency", component: "golang.org/x/net", major: "v0",
    cur: "v0.31.0", fix: "v0.34.0", pri: "P1", sev: "HIGH", cvss: 7.1, epss: 0.0018,
    reach: "true", transitive: true, state: "BLOCKED_UPSTREAM", reason: "BLOCKED_UPSTREAM_FIRST_PARTY",
    firstSeen: "26 Aug", lastSeen: "2 Sep", blockedBy: "wanaware-common", upstreamFp: "d21a77c0be914433",
    tools: ["govulncheck"], new: true,
    impact: "HTTP/2 stream handling permits unbounded header table growth, enabling memory exhaustion.",
    via: "wanaware-common → golang.org/x/net" }),
  mk({ fp: "d21a77c0be914433", id: "CVE-2025-2210", aliases: ["GHSA-2210-xxq4"],
    repo: "wanaware-common", category: "dependency", component: "golang.org/x/net", major: "v0",
    cur: "v0.31.0", fix: "v0.34.0", pri: "P1", sev: "HIGH", cvss: 7.1, epss: 0.0018,
    reach: "true", state: "PR_OPEN", firstSeen: "26 Aug", lastSeen: "2 Sep", pr: "#77", ticket: "#77",
    isUpstream: true, consumers: ["wanaware-api", "wanaware-worker", "ldu-sync", "ops-tools"],
    tools: ["govulncheck", "osv-scanner"], new: false,
    impact: "HTTP/2 stream handling permits unbounded header table growth, enabling memory exhaustion." }),
  mk({ fp: "c9903af1207d5b6e", id: "CVE-2025-1109", aliases: [],
    repo: "wanaware-common", category: "dependency", component: "github.com/go-jose/go-jose", major: "v4",
    cur: "v4.0.2", fix: "v4.0.5", pri: "P1", sev: "HIGH", cvss: 7.5, epss: 0.0031,
    reach: "true", state: "REGRESSED", firstSeen: "22 Jul", lastSeen: "2 Sep", regressed: true,
    tools: ["govulncheck"], seenRuns: 6,
    impact: "JWE decryption accepts unbounded PBES2 iteration counts, permitting CPU exhaustion from an unauthenticated token." }),
  mk({ fp: "e4410bb8c1029d77", id: "gosec-G402", repo: "ldu-sync", category: "code",
    component: "internal/tls/config.go", fn: "NewClientConfig", pri: "P1", sev: "MEDIUM", cvss: 6.5,
    reach: "true", state: "TRIAGED", firstSeen: "2 Sep", lastSeen: "2 Sep", new: true, seenRuns: 1,
    tools: ["gosec"], depClass: "n/a",
    impact: "TLS configuration omits MinVersion, permitting negotiation down to TLS 1.0 against a legacy peer.",
    rem: "Set tls.Config MinVersion to tls.VersionTLS12." }),
  mk({ fp: "f08d2e6a5c114b90", id: "gitleaks-gcp-sa", repo: "ops-tools", category: "secret",
    component: "deploy/legacy/bootstrap.sh", pri: "P0", sev: "CRITICAL", cvss: 9.8,
    reach: "unknown", state: "NEEDS_HUMAN", reason: "NEEDS_HUMAN_SECRET",
    firstSeen: "2 Sep", lastSeen: "2 Sep", ticket: "#901", new: true, seenRuns: 1,
    tools: ["gitleaks"], depClass: "n/a", credType: "GCP service account key",
    impact: "Service account credential committed to source. Removal from the working tree does not undo exposure; rotation is required.",
    restricted: true }),
  mk({ fp: "11ba7730fe9d2a41", id: "GHSA-hcg3-lodash", aliases: ["CVE-2025-8801"],
    repo: "payments-web", category: "dependency", component: "lodash", major: "v4",
    cur: "4.17.20", fix: "4.17.21", pri: "P2", sev: "MEDIUM", cvss: 5.3,
    reach: "unknown", transitive: true, state: "AUTO_REMEDIATING", firstSeen: "19 Aug", lastSeen: "2 Sep",
    tools: ["osv-scanner", "npm-audit"],
    impact: "Prototype pollution in merge helpers. Reachability cannot be determined for this ecosystem." }),
  mk({ fp: "22cd8841af0e3b52", id: "GHSA-vite-dev", repo: "payments-web", category: "dependency",
    component: "vite", major: "v5", cur: "5.2.1", fix: "5.4.6", pri: "P3", sev: "MEDIUM", cvss: 5.9,
    reach: "unknown", depClass: "development", state: "PR_OPEN", firstSeen: "19 Aug", lastSeen: "2 Sep",
    pr: "#233", tools: ["osv-scanner"],
    impact: "Dev server path traversal. Build-time only; not present in the shipped bundle." }),
  mk({ fp: "33de9952b01f4c63", id: "semgrep-react-xss", repo: "payments-web", category: "code",
    component: "src/components/Invoice.tsx", fn: "renderNote", pri: "P1", sev: "HIGH", cvss: 7.2,
    reach: "unknown", state: "NEEDS_HUMAN", reason: "NO_TEST_COVERAGE",
    firstSeen: "26 Aug", lastSeen: "2 Sep", ticket: "#118", tools: ["semgrep"], depClass: "n/a",
    impact: "dangerouslySetInnerHTML receives an unsanitised invoice note field.",
    rem: "Sanitise or render as text. Repository has no executable test suite, so agentic remediation is not permitted." }),
  mk({ fp: "44efaa63c1205d74", id: "GO-2025-2801", repo: "wanaware-worker", category: "dependency",
    component: "google.golang.org/protobuf", major: "v1", cur: "v1.34.1", fix: "v1.36.5",
    pri: "P2", sev: "MEDIUM", cvss: 5.5, reach: "false", transitive: true, state: "TRIAGED",
    firstSeen: "12 Aug", lastSeen: "2 Sep", tools: ["govulncheck", "osv-scanner"],
    impact: "Malformed protobuf input can cause infinite loop. Vulnerable symbol is not reachable from this codebase." }),
  mk({ fp: "55f0bb74d2316e85", id: "GO-2025-2955", repo: "wanaware-worker", category: "dependency",
    component: "github.com/nats-io/nats.go", major: "v1", cur: "v1.36.0", fix: "v1.38.0",
    pri: "P1", sev: "HIGH", cvss: 7.4, reach: "true", state: "MERGED",
    firstSeen: "19 Aug", lastSeen: "26 Aug", pr: "#640", tools: ["govulncheck"],
    impact: "JetStream consumer acknowledgement handling permits message replay under reconnect." }),
  mk({ fp: "66a1cc85e3427f96", id: "trivy-DS002", repo: "wanaware-api", category: "config",
    component: "Dockerfile", pri: "P2", sev: "MEDIUM", cvss: 5.0, reach: "unknown",
    state: "TRIAGED", firstSeen: "5 Aug", lastSeen: "2 Sep", tools: ["trivy"], depClass: "n/a",
    impact: "Image runs as root. Container escape consequences are amplified.",
    rem: "Add a non-root USER directive and set runAsNonRoot in the pod spec." }),
  mk({ fp: "77b2dd96f4538007", id: "actions-mutable-tag", repo: "ldu-sync", category: "config",
    component: ".github/workflows/ci.yml", pri: "P2", sev: "MEDIUM", cvss: 6.1, reach: "unknown",
    state: "NEEDS_HUMAN", reason: "POLICY_ISSUE_ONLY", firstSeen: "5 Aug", lastSeen: "2 Sep",
    ticket: "#88", tools: ["internal"], depClass: "n/a",
    impact: "Third-party action referenced by mutable tag rather than commit SHA.",
    rem: "Pin to commit SHA. Workflow files are deny-listed for automated remediation." }),
  mk({ fp: "88c3ee07a5649118", id: "GO-2024-2887", repo: "ops-tools", category: "dependency",
    component: "github.com/hashicorp/vault-api", major: "v1", cur: "v1.9.0", fix: null,
    pri: "P2", sev: "MEDIUM", cvss: 6.2, reach: "true", state: "NEEDS_HUMAN",
    reason: "NO_UPSTREAM_FIX", firstSeen: "15 Jul", lastSeen: "2 Sep", ticket: "#54",
    tools: ["govulncheck"], seenRuns: 8,
    impact: "Token renewal race under concurrent refresh. No fixed version published upstream." }),
  mk({ fp: "99d4ff18b6750229", id: "GO-2025-3011", repo: "ldu-sync", category: "dependency",
    component: "github.com/neo4j/neo4j-go-driver", major: "v5", cur: "v5.20.0", fix: "v6.0.0",
    pri: "P2", sev: "MEDIUM", cvss: 5.8, reach: "true", state: "NEEDS_HUMAN",
    reason: "MAJOR_BUMP_POLICY", firstSeen: "12 Aug", lastSeen: "2 Sep", ticket: "#91",
    tools: ["govulncheck"],
    impact: "Connection pool does not clear credentials on release. Fix requires a major version upgrade." }),
  mk({ fp: "aae50029c786333a", id: "staticcheck-SA1019", repo: "ops-tools", category: "code",
    component: "cmd/sync/main.go", fn: "loadKey", pri: "P3", sev: "LOW", cvss: 3.1,
    reach: "true", state: "VERIFIED", firstSeen: "22 Jul", lastSeen: "19 Aug", pr: "#31",
    tools: ["staticcheck"], depClass: "n/a", impact: "Deprecated x509 parsing helper in use." }),
  mk({ fp: "bbf6113ad897444b", id: "gosec-G404", repo: "wanaware-api", category: "code",
    component: "internal/token/gen.go", fn: "newSessionID", pri: "P0", sev: "HIGH", cvss: 8.1,
    reach: "true", state: "AUTO_REMEDIATING", firstSeen: "2 Sep", lastSeen: "2 Sep", new: true,
    seenRuns: 1, tools: ["gosec"], depClass: "n/a",
    impact: "Session identifiers generated from math/rand. Values are predictable, permitting session prediction.",
    rem: "Replace with crypto/rand." }),
  mk({ fp: "ccg7224be9a8555c", id: "GO-2025-3106", aliases: ["CVE-2025-22869"],
    repo: "wanaware-worker", category: "dependency", component: "golang.org/x/crypto", major: "v0",
    cur: "v0.35.0", fix: "v0.36.0", pri: "P1", sev: "HIGH", cvss: 7.5, epss: 0.0042, kev: true,
    reach: "false", transitive: true, state: "TRIAGED", firstSeen: "17 Aug", lastSeen: "2 Sep",
    tools: ["govulncheck", "osv-scanner"],
    impact: "Same advisory as the API finding, but the vulnerable symbol is not reachable here." }),
  mk({ fp: "ddh8335cfab9666d", id: "gosec-G104", repo: "ldu-sync", category: "code",
    component: "internal/auth/verify.go", fn: "checkSignature", pri: "P1", sev: "HIGH", cvss: 7.8,
    reach: "true", state: "DECLINED", reason: "DECLINED", firstSeen: "5 Aug", lastSeen: "2 Sep",
    pr: "#204", tools: ["gosec"], depClass: "n/a",
    impact: "Error from signature verification is discarded.",
    rem: "Reviewer closed the automated fix; handled manually in a separate change." }),
  mk({ fp: "eei9446dabca777e", id: "GHSA-axios-ssrf", repo: "payments-web", category: "dependency",
    component: "axios", major: "v1", cur: "1.6.2", fix: "1.7.9", pri: "P1", sev: "HIGH", cvss: 7.5,
    reach: "unknown", state: "PR_OPEN", firstSeen: "26 Aug", lastSeen: "2 Sep", pr: "#241",
    tools: ["osv-scanner", "npm-audit"],
    impact: "Absolute URL in a relative request path permits server-side request forgery." }),
  mk({ fp: "ffj0557ebcdb888f", id: "GO-2025-2990", repo: "wanaware-common", category: "dependency",
    component: "github.com/golang-jwt/jwt", major: "v5", cur: "v5.2.0", fix: "v5.2.2",
    pri: "P0", sev: "CRITICAL", cvss: 9.1, epss: 0.021, kev: true, reach: "true",
    state: "VERIFIED", firstSeen: "12 Aug", lastSeen: "26 Aug", pr: "#71",
    tools: ["govulknot", "govulncheck"],
    impact: "Audience claim validation can be bypassed with a crafted array claim." }),
  mk({ fp: "gg1166fcdec9999a", id: "trivy-KSV012", repo: "wanaware-worker", category: "config",
    component: "deploy/base/worker.yaml", pri: "P3", sev: "LOW", cvss: 3.5, reach: "unknown",
    state: "TRIAGED", firstSeen: "29 Jul", lastSeen: "2 Sep", tools: ["trivy"], depClass: "n/a",
    impact: "readOnlyRootFilesystem is not set on the worker container." }),
  mk({ fp: "hh2277adefa0aaab", id: "GO-2025-2870", repo: "ldu-sync", category: "dependency",
    component: "golang.org/x/net", major: "v0", cur: "v0.31.0", fix: "v0.34.0", pri: "P2",
    sev: "MEDIUM", cvss: 6.4, reach: "unknown", transitive: true, state: "BLOCKED_UPSTREAM",
    reason: "BLOCKED_UPSTREAM_FIRST_PARTY", firstSeen: "26 Aug", lastSeen: "2 Sep",
    blockedBy: "wanaware-common", upstreamFp: "d21a77c0be914433", tools: ["osv-scanner"],
    impact: "Reached through the shared common module." }),
  mk({ fp: "ii3388beafb1bbbc", id: "gosec-G304", repo: "ops-tools", category: "code",
    component: "internal/report/load.go", fn: "readTemplate", pri: "P3", sev: "LOW", cvss: 3.8,
    reach: "true", state: "FALSE_POSITIVE_CANDIDATE", firstSeen: "19 Aug", lastSeen: "2 Sep",
    tools: ["gosec"], depClass: "n/a",
    impact: "File inclusion via variable path.",
    rem: "Nominated as not exploitable: the path is derived from a compile-time constant map, not user input." }),
  mk({ fp: "jj4499cfbac2cccd", id: "GO-2025-3140", repo: "wanaware-api", category: "dependency",
    component: "github.com/jackc/pgx", major: "v5", cur: "v5.5.1", fix: "v5.7.2", pri: "P2",
    sev: "MEDIUM", cvss: 6.0, reach: "false", state: "MERGED", firstSeen: "19 Aug",
    lastSeen: "26 Aug", pr: "#1166", tools: ["govulncheck"],
    impact: "Simple protocol query path permits statement injection when parameters are interpolated." }),
  mk({ fp: "kk5500dacbd3ddde", id: "GO-2025-2775", repo: "ops-tools", category: "dependency",
    component: "github.com/spf13/viper", major: "v1", cur: "v1.18.0", fix: "v1.19.0", pri: "P3",
    sev: "LOW", cvss: 3.3, reach: "false", state: "AUTO_REMEDIATING", firstSeen: "2 Sep",
    lastSeen: "2 Sep", new: true, seenRuns: 1, tools: ["osv-scanner"],
    impact: "Config file permissions not enforced on read." }),
  mk({ fp: "ll6611ebdce4eeef", id: "gosec-G601", repo: "wanaware-worker", category: "code",
    component: "internal/queue/batch.go", fn: "dispatch", pri: "P3", sev: "LOW", cvss: 2.9,
    reach: "true", state: "TRIAGED", firstSeen: "2 Sep", lastSeen: "2 Sep", new: true, seenRuns: 1,
    tools: ["gosec"], depClass: "n/a", impact: "Implicit memory aliasing in a range loop." }),
  mk({ fp: "mm7722fcedf5ffff", id: "GO-2025-3210", repo: "wanaware-api", category: "dependency",
    component: "github.com/redis/go-redis", major: "v9", cur: "v9.3.0", fix: "v9.7.1", pri: "P1",
    sev: "HIGH", cvss: 7.0, reach: "true", state: "TRIAGED", firstSeen: "2 Sep", lastSeen: "2 Sep",
    new: true, seenRuns: 1, tools: ["govulncheck"],
    impact: "Pipeline response desynchronisation under connection reuse can return another client's response." }),
];

const REASON_LABEL = {
  BLOCKED_UPSTREAM_FIRST_PARTY: "Blocked upstream",
  NO_UPSTREAM_FIX: "No upstream fix",
  MAJOR_BUMP_POLICY: "Major bump — policy",
  BUILD_FAILED: "Build failed",
  TESTS_FAILED: "Tests failed",
  NO_TEST_COVERAGE: "No test coverage",
  NEEDS_HUMAN_SECRET: "Needs human — secret",
  POLICY_ISSUE_ONLY: "Ticket only — policy",
  DECLINED: "Declined by reviewer",
  AGENT_GAVE_UP: "Agent gave up",
};
const NOT_FIXED_BARS = [
  ["BLOCKED_UPSTREAM_FIRST_PARTY", 41], ["NO_UPSTREAM_FIX", 33],
  ["MAJOR_BUMP_POLICY", 22], ["BUILD_FAILED", 14],
  ["NO_TEST_COVERAGE", 9], ["DECLINED", 4], ["NEEDS_HUMAN_SECRET", 2],
];

const ROLLUP = [
  { repo: "wanaware-api", tier: 1, lang: "go", found: 47, fixed: 31, open: 16, prs: 4 },
  { repo: "wanaware-common", tier: 1, lang: "go", found: 22, fixed: 18, open: 4, prs: 2 },
  { repo: "wanaware-worker", tier: 1, lang: "go", found: 38, fixed: 26, open: 12, prs: 3 },
  { repo: "ldu-sync", tier: 2, lang: "go", found: 29, fixed: 17, open: 12, prs: 1 },
  { repo: "payments-web", tier: 2, lang: "javascript", found: 64, fixed: 38, open: 26, prs: 2 },
  { repo: "ops-tools", tier: 3, lang: "go", found: 19, fixed: 11, open: 8, prs: 1 },
];

/* ============================================================
   HELPERS
   ============================================================ */
const stateStyle = (s) => {
  const base = { fontFamily: SANS, fontSize: 11, padding: "2px 7px", borderRadius: 3, whiteSpace: "nowrap", display: "inline-block" };
  switch (s) {
    case "PR_OPEN":
    case "AUTO_REMEDIATING":
      return { ...base, border: `1px solid ${T.accent}`, color: T.accent, background: T.accentSoft };
    case "BLOCKED_UPSTREAM":
      return { ...base, border: `1px dashed ${T.p1}`, color: T.p1, background: "#FBF4EC" };
    case "NEEDS_HUMAN":
      return { ...base, border: `1px solid ${T.p0}`, color: "#FFFFFF", background: T.p0 };
    case "VERIFIED":
    case "MERGED":
      return { ...base, border: "1px solid transparent", color: T.faint, background: "#EFF2F4" };
    case "REGRESSED":
      return { ...base, border: `2px solid ${T.p0}`, color: T.p0, background: "#FFFFFF", fontWeight: 600 };
    case "DECLINED":
      return { ...base, border: `1px dotted ${T.faint}`, color: T.faint, background: "#FFFFFF" };
    case "FALSE_POSITIVE_CANDIDATE":
      return { ...base, border: `1px dashed ${T.quiet}`, color: T.quiet, background: "#FFFFFF" };
    default:
      return { ...base, border: `1px solid ${T.rule}`, color: T.quiet, background: "#FFFFFF" };
  }
};
const STATE_LABEL = {
  PR_OPEN: "PR open", AUTO_REMEDIATING: "Remediating", BLOCKED_UPSTREAM: "Blocked",
  NEEDS_HUMAN: "Needs human", VERIFIED: "Verified", MERGED: "Merged",
  REGRESSED: "Regressed", DECLINED: "Declined", TRIAGED: "Triaged",
  FALSE_POSITIVE_CANDIDATE: "FP candidate", DETECTED: "Detected",
};

const REACH_LABEL = { true: "reachable", false: "not reachable", unknown: "reachability unknown" };

function Pri({ p }) {
  return (
    <span style={{
      fontFamily: MONO, fontSize: 11, fontWeight: 600, color: PRI_COLOR[p],
      background: PRI_FILL[p], borderLeft: `3px solid ${PRI_COLOR[p]}`,
      padding: "2px 6px 2px 5px", borderRadius: 2, display: "inline-block",
    }}>{p}</span>
  );
}

function Delta({ v, invert }) {
  if (v === 0) return <span style={{ color: T.faint, fontFamily: MONO, fontSize: 12 }}>±0</span>;
  const good = invert ? v < 0 : v > 0;
  return (
    <span style={{ fontFamily: MONO, fontSize: 12, color: good ? "#2E6B4F" : T.p1 }}>
      {v > 0 ? "+" : ""}{v}
    </span>
  );
}

const Panel = ({ children, style }) => (
  <div style={{ background: T.surface, border: `1px solid ${T.rule}`, borderRadius: 4, ...style }}>{children}</div>
);
const Head = ({ children, right }) => (
  <div className="flex items-center justify-between"
    style={{ padding: "9px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}>
    <span style={{ fontSize: 13, fontWeight: 600, color: T.ink }}>{children}</span>
    {right}
  </div>
);

/* ============================================================
   FILTER MODEL  (VM-UI-F-401, 406, 407, 408)
   ============================================================ */
const DIMENSIONS = [
  { key: "repo", label: "Repository", get: (f) => [f.repo] },
  { key: "tier", label: "Tier", get: (f) => [String(REPOS.find(r => r.name === f.repo)?.tier)] },
  { key: "category", label: "Category", get: (f) => [f.category] },
  { key: "state", label: "State", get: (f) => [f.state] },
  { key: "pri", label: "Priority", get: (f) => [f.pri] },
  { key: "reach", label: "Reachability", get: (f) => [f.reach] },
  { key: "depClass", label: "Dependency class", get: (f) => [f.depClass] },
  { key: "reason", label: "Reason", get: (f) => (f.reason ? [f.reason] : []) },
];
const LABELS = { ...STATE_LABEL, ...REASON_LABEL, true: "Reachable", false: "Not reachable", unknown: "Unknown", production: "Production", development: "Dev only", "n/a": "n/a", dependency: "Dependency", code: "Code", secret: "Secret", config: "Config", 1: "Tier 1", 2: "Tier 2", 3: "Tier 3" };

const RESOLVED = ["VERIFIED", "MERGED", "SUPPRESSED"];
const SWEEP_LABELS = SWEEPS.map((r) => r.label);

// A finding is "observed in" every sweep from its first sighting to its last.
function observedIn(f, runId) {
  const run = SWEEPS.find((r) => r.id === runId);
  if (!run) return false;
  const i = SWEEP_LABELS.indexOf(run.label);
  const a = SWEEP_LABELS.indexOf(f.firstSeen);
  const b = SWEEP_LABELS.indexOf(f.lastSeen);
  return i >= a && i <= b;
}

const LATEST_SWEEP = SWEEPS[SWEEPS.length - 1];
const sweepFor = (label) => SWEEPS[SWEEP_LABELS.indexOf(label)] || LATEST_SWEEP;
// A finding not re-observed in the latest sweep is ambiguous: it may be fixed,
// or its repository may have failed to scan. Both must be visible.
const notReobserved = (f) =>
  f.lastSeen !== LATEST_SWEEP.label && !RESOLVED.includes(f.state);

// Days before the current sweep, keyed by sweep label.
const DAYS_BEFORE = { "15 Jul": 49, "22 Jul": 42, "29 Jul": 35, "5 Aug": 28,
                      "12 Aug": 21, "19 Aug": 14, "26 Aug": 7, "2 Sep": 0 };

// SLA windows in days. Placeholder pending VM-OQ-02.
const SLA = {
  1: { P0: 7,  P1: 14, P2: 30, P3: 90  },
  2: { P0: 14, P1: 30, P2: 60, P3: 90  },
  3: { P0: 30, P1: 60, P2: 90, P3: 180 },
};
const PAUSED = ["NO_UPSTREAM_FIX"];

// Clock starts at detection (VM-NF-302) and stops at VERIFIED (VM-NF-303).
function ageDays(f) {
  const start = DAYS_BEFORE[f.firstSeen] ?? 0;
  if (RESOLVED.includes(f.state)) return start - (DAYS_BEFORE[f.lastSeen] ?? 0);
  return start;
}

function slaStatus(f, tier) {
  const age = ageDays(f), win = SLA[tier][f.pri];
  if (RESOLVED.includes(f.state)) return { text: `closed in ${age}d`, color: T.faint, bold: false };
  if (PAUSED.includes(f.reason)) return { text: "clock paused", color: T.quiet, bold: false };
  if (age > win) return { text: `breach +${age - win}d`, color: T.p0, bold: true };
  if (age > win * 0.75) return { text: `${win - age}d left`, color: T.p1, bold: false };
  return { text: `${win - age}d left`, color: T.faint, bold: false };
}

function inScope(f, scope, scopeRun) {
  if (scope === "all") return true;
  if (scope === "run") return observedIn(f, scopeRun);
  return !RESOLVED.includes(f.state);            // "open"
}

function matches(f, filters, q) {
  for (const d of DIMENSIONS) {
    const sel = filters[d.key];
    if (sel && sel.length && !d.get(f).some((v) => sel.includes(v))) return false;
  }
  if (q && q.trim()) {
    const hay = [f.id, ...(f.aliases || []), f.component, f.repo, f.fn || "", f.fp].join(" ").toLowerCase();
    if (!hay.includes(q.trim().toLowerCase())) return false;
  }
  return true;
}

/* ============================================================
   VIEWS
   ============================================================ */

function RunOverview({ go }) {
  const cur = SWEEPS[SWEEPS.length - 1], prev = SWEEPS[SWEEPS.length - 2];
  const newOnes = FINDINGS.filter((f) => f.new);
  const regressed = FINDINGS.filter((f) => f.regressed);
  const maxBar = NOT_FIXED_BARS[0][1];

  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <div style={{ padding: "12px 14px", borderBottom: `1px solid ${T.ruleSoft}` }}>
          <div className="flex items-center" style={{ fontSize: 13, color: T.ink, gap: 8, flexWrap: "wrap" }}>
            <RunId r={cur} size={14} />
            <span style={{ color: T.faint }}>·</span>
            <span style={{ color: T.quiet }}>{KIND_LABEL[cur.kind]}</span>
            <span style={{ color: T.faint }}>·</span>
            <span style={{ color: T.quiet }}>{cur.repos} repositories</span>
            <span style={{ color: T.faint }}>·</span>
            <span style={{ color: T.quiet }}>12m 30s</span>
            <span style={{ padding: "1px 6px", borderRadius: 3, background: "#E8F0E9", color: "#2E6B4F", fontSize: 11 }}>live</span>
          </div>
          <div style={{ fontFamily: MONO, fontSize: 11, color: T.faint, marginTop: 4 }}>
            scanner {cur.scanner} · tool versions unchanged since S-001246 · previous sweep {prev.id}
          </div>
        </div>

        {/* headline band — one reading, not four cards */}
        <div className="flex" style={{ padding: "16px 14px", gap: 44 }}>
          {[["Found", cur.found, cur.found - prev.found, false],
            ["Fixed", cur.fixed, cur.fixed - prev.fixed, false],
            ["Not fixed", cur.notFixed, cur.notFixed - prev.notFixed, true]].map(([l, v, d, inv]) => (
            <button key={l} onClick={() => go("findings", l === "Found" ? { _scope: "run", _run: cur.id } : { _scope: "open" })} className="text-left"
              style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}>
              <div style={{ fontSize: 12, color: T.quiet }}>{l}</div>
              <div className="flex items-baseline gap-2">
                <span style={{ fontFamily: MONO, fontSize: 26, color: T.ink, letterSpacing: -0.5 }}>{v}</span>
                <Delta v={d} invert={inv} />
              </div>
            </button>
          ))}
        </div>
      </Panel>

      {/* coverage gaps sit above the rollup — VM-UI-F-206 */}
      <div style={{ background: "#FBF4EC", border: `1px solid ${T.p1}`, borderRadius: 4, padding: "10px 12px" }}
        className="flex items-center justify-between">
        <div style={{ fontSize: 13, color: T.ink }}>
          <strong style={{ color: T.p1 }}>2 repositories not scanned</strong>
          <span style={{ color: T.quiet }}> — payments-web (clone timeout), ops-tools (govulncheck exit 2)</span>
        </div>
        <button onClick={() => go("gaps")} style={{ fontSize: 12, color: T.accent, background: "none", border: "none", cursor: "pointer" }}>
          View gaps
        </button>
      </div>

      <div className="flex gap-3" style={{ flexWrap: "wrap" }}>
        <Panel style={{ flex: "1 1 340px", minWidth: 300 }}>
          <Head right={<span style={{ fontFamily: MONO, fontSize: 12, color: T.quiet }}>{newOnes.length}</span>}>New this run</Head>
          <div>
            {newOnes.map((f) => <MiniRow key={f.fp} f={f} go={go} />)}
          </div>
        </Panel>
        <Panel style={{ flex: "1 1 340px", minWidth: 300 }}>
          <Head right={<span style={{ fontFamily: MONO, fontSize: 12, color: T.p0 }}>{regressed.length}</span>}>
            Regressed
          </Head>
          <div>
            {regressed.map((f) => <MiniRow key={f.fp} f={f} go={go} />)}
            <div style={{ padding: "10px 12px", fontSize: 12, color: T.quiet }}>
              Previously verified, observed again. Distinct from a new finding.
            </div>
          </div>
        </Panel>
      </div>

      <Panel>
        <Head>Not fixed by reason</Head>
        <div style={{ padding: "10px 12px" }}>
          {NOT_FIXED_BARS.map(([k, n]) => (
            <button key={k} onClick={() => go("findings", { reason: [k], _scope: "open" })}
              className="flex items-center w-full text-left"
              style={{ background: "none", border: "none", padding: "4px 0", cursor: "pointer", gap: 10 }}>
              <span style={{ fontSize: 12, color: T.ink, width: 168, flexShrink: 0 }}>{REASON_LABEL[k]}</span>
              <span style={{ fontFamily: MONO, fontSize: 12, color: T.quiet, width: 28, textAlign: "right", flexShrink: 0 }}>{n}</span>
              <span style={{ flex: 1, height: 8, background: T.ruleSoft, borderRadius: 1, overflow: "hidden" }}>
                <span style={{ display: "block", height: "100%", width: `${(n / maxBar) * 100}%`, background: k === "NEEDS_HUMAN_SECRET" ? T.p0 : T.accent, opacity: k === "NEEDS_HUMAN_SECRET" ? 1 : 0.55 }} />
              </span>
            </button>
          ))}
        </div>
      </Panel>

      <Panel>
        <Head>Repositories</Head>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ color: T.quiet, fontSize: 11 }}>
              {["Repository", "Tier", "Lang", "Found", "Fixed", "Open", "PRs"].map((h, i) => (
                <th key={h} style={{ textAlign: i > 2 ? "right" : "left", padding: "6px 12px", fontWeight: 500, borderBottom: `1px solid ${T.ruleSoft}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ROLLUP.map((r) => (
              <tr key={r.repo} style={{ cursor: "pointer" }} onClick={() => go("repo", r.repo)}>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.accent }}>{r.repo}</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, color: T.quiet }}>{r.tier}</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, color: T.quiet, fontSize: 12 }}>{r.lang}</td>
                {[r.found, r.fixed, r.open, r.prs].map((v, i) => (
                  <td key={i} style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 12, color: T.ink }}>{v}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel>
        <Head>Token and cost</Head>
        <div className="flex" style={{ padding: "12px 14px", gap: 40, flexWrap: "wrap" }}>
          {[["Input", "1.42M"], ["Output", "89K"], ["Cache read", "4.10M"], ["Total", "$18.40"],
            ["Per finding fixed", "$0.80"], ["Per abandoned attempt", "$2.10"]].map(([l, v]) => (
            <div key={l}>
              <div style={{ fontSize: 11, color: T.quiet }}>{l}</div>
              <div style={{ fontFamily: MONO, fontSize: 15, color: T.ink }}>{v}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function MiniRow({ f, go }) {
  return (
    <button onClick={() => go("finding", f.fp)} className="flex items-center w-full text-left"
      style={{ background: "none", border: "none", borderBottom: `1px solid ${T.ruleSoft}`, padding: "7px 12px", gap: 8, cursor: "pointer" }}>
      <Pri p={f.pri} />
      <span style={{ fontFamily: MONO, fontSize: 12, color: T.ink, flex: "0 0 auto" }}>{f.id}</span>
      <span style={{ fontFamily: MONO, fontSize: 12, color: T.quiet, marginLeft: "auto" }} className="truncate">{f.repo}</span>
    </button>
  );
}

/* ---------- Explorer ---------- */

function Explorer({ filters, setFilters, q, setQ, scope, setScope, scopeRun, setScopeRun, go }) {
  const [sort, setSort] = useState("priority");
  const [open, setOpen] = useState(null);

  const pool = useMemo(
    () => FINDINGS.filter((f) => inScope(f, scope, scopeRun)), [scope, scopeRun]);

  const results = useMemo(
    () => {
      const r = pool.filter((f) => matches(f, filters, q));
      const order = { P0: 0, P1: 1, P2: 2, P3: 3 };
      if (sort === "priority") r.sort((a, b) => order[a.pri] - order[b.pri] || a.repo.localeCompare(b.repo));
      if (sort === "repo") r.sort((a, b) => a.repo.localeCompare(b.repo) || order[a.pri] - order[b.pri]);
      if (sort === "severity") r.sort((a, b) => b.cvss - a.cvss);
      return r;
    }, [pool, filters, q, sort]);

  // facet counts respect all OTHER active dimensions — VM-UI-F-408
  const facets = useMemo(() => {
    const out = {};
    for (const d of DIMENSIONS) {
      const others = { ...filters }; delete others[d.key];
      const sub = pool.filter((f) => matches(f, others, q));
      const counts = {};
      for (const f of sub) for (const v of d.get(f)) counts[v] = (counts[v] || 0) + 1;
      const all = new Set();
      for (const f of FINDINGS) for (const v of d.get(f)) all.add(v);
      out[d.key] = [...all].sort().map((v) => ({ v, n: counts[v] || 0 }));
    }
    return out;
  }, [pool, filters, q]);

  const toggle = (dim, v) => {
    const cur = filters[dim] || [];
    const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
    const f = { ...filters };
    if (next.length) f[dim] = next; else delete f[dim];
    setFilters(f);
  };

  const activeChips = Object.entries(filters).flatMap(([k, vs]) =>
    vs.map((v) => ({ k, v, label: `${k}:${LABELS[v] || v}` })));

  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <div className="flex items-center" style={{ padding: "9px 12px", borderBottom: `1px solid ${T.ruleSoft}`, gap: 10, flexWrap: "wrap" }}>
          <span style={{ fontSize: 12, color: T.quiet }}>Showing</span>
          <div className="flex" style={{ border: `1px solid ${T.rule}`, borderRadius: 3, overflow: "hidden" }}>
            {[["open", "Open · all runs"], ["run", "One run"], ["all", "Everything"]].map(([k, l]) => (
              <button key={k} onClick={() => setScope(k)}
                style={{
                  fontSize: 12, padding: "4px 11px", border: "none", cursor: "pointer",
                  background: scope === k ? T.accent : T.surface,
                  color: scope === k ? "#FFFFFF" : T.ink,
                  borderRight: k !== "all" ? `1px solid ${T.rule}` : "none",
                }}>{l}</button>
            ))}
          </div>
          {scope === "run" && (
            <select value={scopeRun} onChange={(e) => setScopeRun(e.target.value)}
              style={{ fontFamily: MONO, fontSize: 12, padding: "4px 6px", border: `1px solid ${T.rule}`, borderRadius: 3, background: T.surface, color: T.ink }}>
              {[...SWEEPS].reverse().map((r) => (
                <option key={r.id} value={r.id}>{r.id} · {r.time}</option>
              ))}
            </select>
          )}
          <span style={{ fontSize: 11, color: T.faint, marginLeft: "auto", maxWidth: 380, textAlign: "right" }}>
            {scope === "open" && `Not yet resolved, across all ${SWEEPS.length} sweeps. Excludes ${FINDINGS.filter((f) => RESOLVED.includes(f.state)).length} verified or merged.`}
            {scope === "run" && `Observed in ${scopeRun}, any state — a point-in-time view, not current fleet risk.`}
            {scope === "all" && `Every finding ever recorded, every state. Audit view.`}
          </span>
        </div>
        <div style={{ padding: "10px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="Search identifier, alias, module, file, repository…"
            style={{
              width: "100%", fontFamily: MONO, fontSize: 13, padding: "7px 10px",
              border: `1px solid ${T.rule}`, borderRadius: 3, color: T.ink, outline: "none", background: T.ground,
            }} />
          <div style={{ fontSize: 11, color: T.faint, marginTop: 5 }}>
            Aliases are indexed — searching CVE-2025-22869 returns the finding filed as GO-2025-3106.
          </div>
        </div>

        <div className="flex" style={{ padding: "8px 12px", gap: 6, flexWrap: "wrap", borderBottom: `1px solid ${T.ruleSoft}` }}>
          {DIMENSIONS.map((d) => (
            <div key={d.key} style={{ position: "relative" }}>
              <button onClick={() => setOpen(open === d.key ? null : d.key)}
                style={{
                  fontSize: 12, padding: "4px 9px", borderRadius: 3, cursor: "pointer",
                  border: `1px solid ${filters[d.key] ? T.accent : T.rule}`,
                  background: filters[d.key] ? T.accentSoft : T.surface,
                  color: filters[d.key] ? T.accent : T.ink,
                }}>
                {d.label}{filters[d.key] ? ` (${filters[d.key].length})` : ""}
              </button>
              {open === d.key && (
                <div style={{
                  position: "absolute", zIndex: 20, top: 30, left: 0, minWidth: 210,
                  background: T.surface, border: `1px solid ${T.rule}`, borderRadius: 4,
                  boxShadow: "0 2px 8px rgba(26,32,39,0.10)", padding: 4, maxHeight: 280, overflowY: "auto",
                }}>
                  {facets[d.key].map(({ v, n }) => {
                    const sel = (filters[d.key] || []).includes(v);
                    const dead = n === 0 && !sel;
                    return (
                      <button key={v} disabled={dead} onClick={() => toggle(d.key, v)}
                        className="flex items-center justify-between w-full"
                        style={{
                          fontSize: 12, padding: "5px 8px", border: "none", borderRadius: 3,
                          background: sel ? T.accentSoft : "transparent",
                          color: dead ? "#C2C9D0" : sel ? T.accent : T.ink,
                          cursor: dead ? "not-allowed" : "pointer", textAlign: "left",
                        }}>
                        <span className="truncate" style={{ fontFamily: d.key === "repo" ? MONO : SANS }}>
                          {sel ? "✓ " : ""}{LABELS[v] || v}
                        </span>
                        <span style={{ fontFamily: MONO, fontSize: 11, color: dead ? "#C2C9D0" : T.faint, marginLeft: 10 }}>{n}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          ))}
          <div style={{ marginLeft: "auto" }}>
            <select value={sort} onChange={(e) => setSort(e.target.value)}
              style={{ fontSize: 12, padding: "4px 6px", border: `1px solid ${T.rule}`, borderRadius: 3, background: T.surface, color: T.ink }}>
              <option value="priority">Sort: priority</option>
              <option value="severity">Sort: severity</option>
              <option value="repo">Sort: repository</option>
            </select>
          </div>
        </div>

        {activeChips.length > 0 && (
          <div className="flex items-center" style={{ padding: "7px 12px", gap: 6, flexWrap: "wrap", borderBottom: `1px solid ${T.ruleSoft}` }}>
            {activeChips.map((c) => (
              <button key={c.k + c.v} onClick={() => toggle(c.k, c.v)}
                style={{ fontFamily: MONO, fontSize: 11, padding: "2px 7px", borderRadius: 3, border: `1px solid ${T.accent}`, background: T.accentSoft, color: T.accent, cursor: "pointer" }}>
                {c.label} ×
              </button>
            ))}
            <button onClick={() => { setFilters({}); setQ(""); }}
              style={{ fontSize: 11, color: T.quiet, background: "none", border: "none", cursor: "pointer", textDecoration: "underline" }}>
              clear all
            </button>
          </div>
        )}

        <div className="flex items-center justify-between" style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}>
          <span style={{ fontFamily: MONO, fontSize: 12, color: T.quiet }}>
            {results.length} of {pool.length} in scope
            {pool.length !== FINDINGS.length && (
              <span style={{ color: T.faint }}> · {FINDINGS.length} total</span>
            )}
          </span>
          <span style={{ fontSize: 11, color: T.faint }}>
            {scope === "open" ? "Open · all runs"
              : scope === "run" ? `Run ${scopeRun}` : "All findings, all states"}
          </span>
        </div>

        {results.length === 0 ? (
          <div style={{ padding: "40px 12px", textAlign: "center" }}>
            <div style={{ fontSize: 14, color: T.ink, marginBottom: 4 }}>No findings match this filter</div>
            <div style={{ fontSize: 12, color: T.quiet }}>Remove a filter or widen the search to see results.</div>
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ fontSize: 11, color: T.quiet }}>
                {["", "Identifier", "Repository", "Component", "Seen (sweep #)", "Reach", "State"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "6px 12px", fontWeight: 500, borderBottom: `1px solid ${T.ruleSoft}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((f) => (
                <tr key={f.fp} onClick={() => go("finding", f.fp)} style={{ cursor: "pointer" }}>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}><Pri p={f.pri} /></td>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.ink }}>
                    {f.id}
                    {f.aliases?.length > 0 && <span style={{ color: T.faint }}> +{f.aliases.length}</span>}
                  </td>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.accent }}>{f.repo}</td>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.quiet, maxWidth: 260 }} className="truncate">
                    {f.component}{f.major ? `@${f.major}` : ""}
                  </td>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, whiteSpace: "nowrap" }}>
                    <span style={{ color: T.faint }}>{sweepFor(f.firstSeen).id.slice(-4)}</span>
                    <span style={{ color: "#C2C9D0" }}> → </span>
                    <span style={{ color: notReobserved(f) ? T.p1 : T.ink }}>
                      {sweepFor(f.lastSeen).id.slice(-4)}
                    </span>
                    {notReobserved(f) && <span style={{ color: T.p1 }}> ▪</span>}
                  </td>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontSize: 11, color: f.reach === "true" ? T.p1 : T.faint }}>
                    {f.reach === "true" ? "yes" : f.reach === "false" ? "no" : "unknown"}
                  </td>
                  <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}>
                    <span style={stateStyle(f.state)}>{STATE_LABEL[f.state]}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {results.length > 0 && (
          <div style={{ padding: "8px 12px", borderTop: `1px solid ${T.ruleSoft}`, fontSize: 11, color: T.faint, lineHeight: 1.55 }}>
            Seen column shows the sweep a finding first appeared in and the sweep that last observed it.
            All sweeps carry the <span style={{ fontFamily: MONO }}>S-00</span> prefix.
            <span style={{ color: T.p1 }}> ▪</span> marks a finding not re-observed in {LATEST_SWEEP.id} while still unresolved —
            it may be fixed, or its repository may have failed to scan. Check coverage gaps before assuming the former.
            {scope === "run" && (
              <span style={{ display: "block", marginTop: 4, color: T.p1 }}>
                Scope is {scopeRun}, but the State and last-seen columns show live values, not state as of that run.
              </span>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}

/* ---------- Finding detail ---------- */

function FindingDetail({ fp, go }) {
  const f = FINDINGS.find((x) => x.fp === fp);
  const [ev, setEv] = useState(false);
  if (!f) return <Panel><div style={{ padding: 20 }}>Not found.</div></Panel>;

  const tier = REPOS.find((r) => r.name === f.repo)?.tier || 3;
  const tierMul = tier === 1 ? 1.2 : tier === 2 ? 1.0 : 0.8;
  const reachMul = f.reach === "true" ? 1.0 : f.reach === "unknown" ? 0.5 : 0.25;
  const depMul = f.depClass === "development" ? 0.4 : 1.0;
  const score = ((f.cvss + (f.kev ? 3 : 0) + 2 * f.epss) * reachMul * depMul * tierMul).toFixed(1);

  const timeline = [
    { t: `${f.firstSeen} 03:12`, s: "Detected", a: "scanworker" },
    { t: `${f.firstSeen} 03:41`, s: "Triaged", a: "triage" },
    ...(["AUTO_REMEDIATING", "PR_OPEN", "MERGED", "VERIFIED"].includes(f.state)
      ? [{ t: `${f.firstSeen} 04:02`, s: "Auto remediating", a: "orchestrator · policy rule 6" }] : []),
    ...(f.pr ? [{ t: `${f.firstSeen} 04:19`, s: "PR open", a: `fixworker · PR ${f.pr}` }] : []),
    ...(["MERGED", "VERIFIED"].includes(f.state) ? [{ t: `${f.lastSeen} 11:04`, s: "Merged", a: "orchestrator" }] : []),
    ...(f.state === "VERIFIED" ? [{ t: `${f.lastSeen} 03:20`, s: "Verified", a: "scanworker" }] : []),
    ...(f.state === "BLOCKED_UPSTREAM" ? [{ t: `${f.firstSeen} 03:44`, s: "Blocked upstream", a: `orchestrator · ${f.blockedBy}` }] : []),
    ...(f.state === "NEEDS_HUMAN" ? [{ t: `${f.firstSeen} 03:44`, s: "Needs human", a: `policy · ${REASON_LABEL[f.reason] || ""}` }] : []),
    ...(f.state === "DECLINED" ? [{ t: `${f.lastSeen} 09:12`, s: "Declined", a: "reviewer closed PR unmerged" }] : []),
    ...(f.state === "REGRESSED" ? [{ t: `${f.lastSeen} 03:14`, s: "Regressed", a: "scanworker · observed again" }] : []),
  ];

  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <div style={{ padding: "14px 16px" }}>
          <div className="flex items-start justify-between" style={{ gap: 12 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontFamily: MONO, fontSize: 20, color: T.ink }}>{f.id}</div>
              {f.aliases?.length > 0 && (
                <div style={{ fontFamily: MONO, fontSize: 12, color: T.quiet, marginTop: 3 }}>
                  also {f.aliases.join(" · ")}
                </div>
              )}
            </div>
            <div className="flex items-center" style={{ gap: 8, flexShrink: 0 }}>
              <Pri p={f.pri} />
              <span style={stateStyle(f.state)}>{STATE_LABEL[f.state]}</span>
            </div>
          </div>

          <div style={{ fontFamily: MONO, fontSize: 11, color: T.faint, marginTop: 8 }}>
            fingerprint {f.fp} ⧉ · reported by {f.tools.join(", ")}
          </div>

          <div style={{ marginTop: 14, paddingTop: 12, borderTop: `1px solid ${T.ruleSoft}` }}>
            <div style={{ fontFamily: MONO, fontSize: 14, color: T.ink }}>
              {f.component}{f.fn ? ` · ${f.fn}()` : ""}
            </div>
            {f.cur && (
              <div style={{ fontFamily: MONO, fontSize: 13, color: T.quiet, marginTop: 3 }}>
                {f.cur} {f.fix ? `→ ${f.fix}` : "→ no fixed version published"}
              </div>
            )}
            <div style={{ fontSize: 12, color: T.quiet, marginTop: 6 }}>
              {f.depClass !== "n/a" && <>{f.depClass} · {f.transitive ? "transitive" : "direct"} · </>}
              <span style={{ color: f.reach === "true" ? T.p1 : f.reach === "unknown" ? T.quiet : T.faint, fontWeight: f.reach === "unknown" ? 500 : 400 }}>
                {REACH_LABEL[f.reach]}
              </span>
              {f.kev && <span style={{ color: T.p0 }}> · in known-exploited catalogue</span>}
            </div>
          </div>
        </div>
      </Panel>

      <div className="flex gap-3" style={{ flexWrap: "wrap" }}>
        <Panel style={{ flex: "1 1 300px", minWidth: 280 }}>
          <Head right={<span style={{ fontFamily: MONO, fontSize: 15, color: PRI_COLOR[f.pri] }}>{score}</span>}>Score decomposition</Head>
          <div style={{ padding: "10px 12px" }}>
            {[["base (CVSS)", f.cvss.toFixed(1), "+"],
              ["known exploited", f.kev ? "3.0" : "0.0", "+"],
              ["epss", (2 * f.epss).toFixed(3), "+"],
              [REACH_LABEL[f.reach], reachMul.toFixed(2), "×"],
              [f.depClass === "n/a" ? "n/a" : f.depClass, depMul.toFixed(2), "×"],
              [`tier ${tier}`, tierMul.toFixed(2), "×"]].map(([l, v, op]) => (
              <div key={l} className="flex items-center justify-between" style={{ padding: "3px 0", fontSize: 12 }}>
                <span style={{ color: T.quiet }}>{l}</span>
                <span style={{ fontFamily: MONO, color: T.ink }}>{op} {v}</span>
              </div>
            ))}
            <div style={{ fontSize: 11, color: T.faint, marginTop: 8, paddingTop: 8, borderTop: `1px solid ${T.ruleSoft}` }}>
              P0 ≥ 9.0 · P1 ≥ 7.0 · P2 ≥ 4.0
            </div>
          </div>
        </Panel>

        <Panel style={{ flex: "2 1 380px", minWidth: 320 }}>
          <Head>Impact</Head>
          <div style={{ padding: "10px 12px", fontSize: 13, color: T.ink, lineHeight: 1.55, maxWidth: "72ch" }}>
            {f.impact}
            {f.rem && <div style={{ marginTop: 10, color: T.quiet }}>{f.rem}</div>}
            {f.via && (
              <div style={{ marginTop: 10, fontFamily: MONO, fontSize: 12, color: T.quiet }}>
                pulled in via {f.via}
              </div>
            )}
            {f.credType && (
              <div style={{ marginTop: 10, padding: "8px 10px", background: "#F4E7E9", borderRadius: 3, fontSize: 12, color: T.p0 }}>
                {f.credType} at {f.component}. The value is never stored, transmitted, or displayed. Rotation is required.
              </div>
            )}
          </div>
        </Panel>
      </div>

      {(f.blockedBy || f.isUpstream) && (
        <Panel>
          <Head>First-party module</Head>
          <div style={{ padding: "10px 12px", fontSize: 13 }}>
            {f.blockedBy ? (
              <>
                <span style={{ color: T.quiet }}>Blocked on the upstream fix in </span>
                <button onClick={() => go("finding", f.upstreamFp)}
                  style={{ fontFamily: MONO, color: T.accent, background: "none", border: "none", padding: 0, cursor: "pointer" }}>
                  {f.blockedBy}
                </button>
                <span style={{ color: T.quiet }}>. No consumer pull request is opened in Wave 1.</span>
              </>
            ) : (
              <>
                <div style={{ color: T.quiet, marginBottom: 6 }}>
                  Wave 1 fix. {f.consumers.length} consumers blocked until this is published.
                </div>
                <div className="flex" style={{ gap: 6, flexWrap: "wrap" }}>
                  {f.consumers.map((c) => (
                    <span key={c} style={{ fontFamily: MONO, fontSize: 11, padding: "2px 7px", borderRadius: 3, border: `1px dashed ${T.p1}`, color: T.p1 }}>{c}</span>
                  ))}
                </div>
              </>
            )}
          </div>
        </Panel>
      )}

      <div className="flex gap-3" style={{ flexWrap: "wrap" }}>
        <Panel style={{ flex: "1 1 340px", minWidth: 300 }}>
          <Head>Lifecycle</Head>
          <div style={{ padding: "10px 12px" }}>
            {timeline.map((e, i) => (
              <div key={i} className="flex" style={{ gap: 10, padding: "4px 0", fontSize: 12 }}>
                <span style={{ fontFamily: MONO, color: T.faint, width: 84, flexShrink: 0 }}>{e.t}</span>
                <span style={{ color: T.ink, width: 116, flexShrink: 0 }}>{e.s}</span>
                <span style={{ color: T.quiet }} className="truncate">{e.a}</span>
              </div>
            ))}
            <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${T.ruleSoft}`, fontSize: 12, color: T.quiet }}>
              Observed in {f.seenRuns} runs · first S-{String(1247 - f.seenRuns + 1).padStart(6, "0")} ({f.firstSeen}), last S-001247 ({f.lastSeen})
            </div>
          </div>
        </Panel>

        <Panel style={{ flex: "1 1 340px", minWidth: 300 }}>
          <Head>Remediation attempts</Head>
          <div style={{ padding: "10px 12px" }}>
            {f.pr ? (
              <>
                <div className="flex items-center" style={{ gap: 10, fontSize: 12, flexWrap: "wrap" }}>
                  <span style={{ fontFamily: MONO, color: T.faint }}>{f.firstSeen}</span>
                  <span style={{ color: T.ink }}>{f.category === "code" ? "agentic" : "deterministic"}</span>
                  <span style={{ fontFamily: MONO, color: T.accent }}>PR {f.pr}</span>
                  <span style={{ color: "#2E6B4F" }}>build ✓ tests ✓ scan clean ✓</span>
                  <button onClick={() => setEv(!ev)} style={{ fontSize: 11, color: T.accent, background: "none", border: "none", cursor: "pointer" }}>
                    {ev ? "hide evidence" : "evidence"}
                  </button>
                </div>
                {ev && (
                  <pre style={{
                    marginTop: 8, background: "#F4F6F8", border: `1px solid ${T.rule}`, borderRadius: 3,
                    padding: 10, fontFamily: MONO, fontSize: 11, color: T.ink, overflowX: "auto", maxHeight: 180,
                  }}>{`$ go build ./...
$ go vet ./...
$ go test ./... -race -count=1
ok  	github.com/org/${f.repo}/internal/...	4.221s
$ go mod tidy && git diff --exit-code go.mod go.sum
$ go mod verify
all modules verified
$ govulncheck ./...
No vulnerabilities found.`}</pre>
                )}
              </>
            ) : (
              <div style={{ fontSize: 12, color: T.quiet }}>
                No attempt made. {f.reason ? REASON_LABEL[f.reason] : "Awaiting policy evaluation."}
              </div>
            )}
          </div>
        </Panel>
      </div>

      <div className="flex" style={{ gap: 14, fontSize: 12, padding: "0 2px" }}>
        {f.pr && <span style={{ color: T.accent }}>Pull request {f.pr}</span>}
        {f.ticket && <span style={{ color: T.accent }}>Ticket {f.ticket}</span>}
        <span style={{ color: T.accent }}>Advisory</span>
        <span style={{ color: T.accent }}>Report archive</span>
      </div>
    </div>
  );
}

/* ---------- Runs & trends ---------- */

function Runs({ go }) {
  const data = SWEEPS.map((r) => ({ name: r.id.slice(-4), open: r.notFixed, fixed: r.fixed, found: r.found, id: r.id }));
  const changeAt = SWEEPS.filter((r) => r.scannerChanged).map((r) => r.id.slice(-4));
  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <Head right={<span style={{ fontSize: 11, color: T.faint }}>sweeps only · vertical rules mark scanner image changes</span>}>
          Fleet trend
        </Head>
        <div style={{ padding: "14px 8px 8px 0", height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 4, right: 20, bottom: 4, left: 4 }}>
              <CartesianGrid stroke={T.ruleSoft} vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: T.quiet }} stroke={T.rule} />
              <YAxis tick={{ fontSize: 11, fill: T.quiet }} stroke={T.rule} />
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 3, border: `1px solid ${T.rule}` }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {changeAt.map((c) => (
                <ReferenceLine key={c} x={c} stroke={T.p1} strokeDasharray="3 3" />
              ))}
              <Line type="monotone" dataKey="found" name="Found" stroke={T.quiet} strokeWidth={1.5} dot={false} />
              <Line type="monotone" dataKey="open" name="Not fixed" stroke={T.p0} strokeWidth={2} dot={{ r: 2 }} />
              <Line type="monotone" dataKey="fixed" name="Fixed" stroke={T.accent} strokeWidth={2} dot={{ r: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <Panel>
        <Head>Run history</Head>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ fontSize: 11, color: T.quiet }}>
              {["Run", "Started (UTC)", "Kind", "Repos", "Found", "Fixed", "Not fixed", "Scanner", ""].map((h, i) => (
                <th key={h} style={{ textAlign: i > 2 && i < 7 ? "right" : "left", padding: "6px 12px", fontWeight: 500, borderBottom: `1px solid ${T.ruleSoft}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[...RUNS].reverse().map((r) => (
              <tr key={r.id} onClick={() => go(r.current ? "current" : "snapshot", r.id)} style={{ cursor: "pointer" }}>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, whiteSpace: "nowrap" }}>
                  <span style={{ fontFamily: MONO, fontSize: 12, fontWeight: 600, color: KIND_INK[r.kind], background: KIND_TINT[r.kind], padding: "1px 6px", borderRadius: 3 }}>{r.id}</span>
                  {r.current && <span style={{ marginLeft: 8, fontSize: 10, padding: "1px 5px", borderRadius: 3, background: "#E8F0E9", color: "#2E6B4F" }}>live</span>}
                </td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, color: T.quiet, whiteSpace: "nowrap" }}>{r.time}</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontSize: 11, color: KIND_INK[r.kind] }}>
                  {KIND_LABEL[r.kind]}{r.advisory ? ` · ${r.advisory}` : ""}{r.actor ? ` · ${r.actor}` : ""}
                </td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 12, color: r.failed ? T.p1 : T.ink }}>
                  {r.repos}{r.failed ? ` −${r.failed}` : ""}
                </td>
                {[r.found, r.fixed, r.notFixed].map((v, i) => (
                  <td key={i} style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 12 }}>{v}</td>
                ))}
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, color: T.faint }}>
                  {r.scanner}{r.scannerChanged ? " ←changed" : ""}
                </td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontSize: 11, color: r.failed ? T.p1 : T.faint }}>
                  {r.failed ? "partial" : "complete"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function Snapshot({ runId, go }) {
  const r = RUNS.find((x) => x.id === runId) || RUNS[0];
  const peers = RUNS.filter((x) => x.kind === r.kind);
  const prev = peers[peers.indexOf(r) - 1];
  return (
    <div className="flex flex-col gap-3">
      <div style={{ background: "#EEF1F4", border: `1px solid ${T.rule}`, borderRadius: 4, padding: "9px 12px", fontSize: 12, color: T.quiet }}>
        <strong style={{ color: T.ink }}>Snapshot.</strong> State as recorded at this run, not current state.
        A finding fixed after {r.id} still shows as open here.
      </div>
      <Panel>
        <div style={{ padding: "12px 14px", borderBottom: `1px solid ${T.ruleSoft}` }}>
          <div className="flex items-center" style={{ gap: 8, flexWrap: "wrap" }}>
            <RunId r={r} size={14} />
            <span style={{ color: T.faint }}>·</span>
            <span style={{ fontSize: 13, color: T.quiet }}>{KIND_LABEL[r.kind]} · {r.repos} repositories</span>
          </div>
          <div style={{ fontFamily: MONO, fontSize: 11, color: T.faint, marginTop: 5 }}>scanner {r.scanner}</div>
        </div>
        <div className="flex" style={{ padding: "16px 14px", gap: 44 }}>
          {[["Found", r.found, prev ? r.found - prev.found : 0, false],
            ["Fixed", r.fixed, prev ? r.fixed - prev.fixed : 0, false],
            ["Not fixed", r.notFixed, prev ? r.notFixed - prev.notFixed : 0, true]].map(([l, v, d, inv]) => (
            <div key={l}>
              <div style={{ fontSize: 12, color: T.quiet }}>{l}</div>
              <div className="flex items-baseline gap-2">
                <span style={{ fontFamily: MONO, fontSize: 26, color: T.ink, letterSpacing: -0.5 }}>{v}</span>
                <Delta v={d} invert={inv} />
              </div>
            </div>
          ))}
        </div>
      </Panel>
      {r.failed > 0 && (
        <div style={{ background: "#FBF4EC", border: `1px solid ${T.p1}`, borderRadius: 4, padding: "10px 12px", fontSize: 13, color: T.ink }}>
          <strong style={{ color: T.p1 }}>Partial run.</strong> {r.failed} repositor{r.failed === 1 ? "y" : "ies"} failed to scan. Counts are not comparable to a complete run.
        </div>
      )}
      <button onClick={() => go("runs")} style={{ alignSelf: "flex-start", fontSize: 12, color: T.accent, background: "none", border: "none", cursor: "pointer" }}>
        ← back to run history
      </button>
    </div>
  );
}

/* ---------- Waves & gaps ---------- */

const WAVES = [{
  fp: "d21a77c0be914433",
  cve: "CVE-2025-2210", aliases: ["GHSA-2210-xxq4"], pri: "P1", cvss: 7.1,
  dep: "golang.org/x/net", cur: "v0.31.0", fix: "v0.34.0",
  module: "github.com/org/common", owner: "wanaware-common", ownerVer: "v1.4.1",
  wave1: { pr: "#77", state: "PR_OPEN", ageDays: 7 },
  trigger: "tag",
  consumers: [
    { repo: "wanaware-api",    tier: 1, reach: "true",    state: "blocked",  ver: "v1.4.1", fp: "b71c04ea99d3f218" },
    { repo: "wanaware-worker", tier: 1, reach: "true",    state: "blocked",  ver: "v1.4.1" },
    { repo: "ldu-sync",        tier: 2, reach: "unknown", state: "blocked",  ver: "v1.3.9", fp: "hh2277adefa0aaab" },
    { repo: "ops-tools",       tier: 3, reach: "false",   state: "excluded", ver: "replace → ../common",
      why: "replace directive pins the module to a local path; Wave 2 cannot resolve it" },
  ],
}];

const REACH_STROKE = { true: T.p0, unknown: T.p1, false: T.faint, "n/a": T.faint };
const REACH_WORD = { true: "reaches vulnerable code", unknown: "reachability unknown", false: "does not reach it", "n/a": "—" };

function BlastRadius({ w, go }) {
  const cs = w.consumers;
  const n = cs.length;
  const W = 720, cw = 158, gap = (W - 24 - n * cw) / (n - 1);
  const xs = cs.map((_, i) => 12 + i * (cw + gap));
  const modCx = W / 2;

  return (
    <svg viewBox={`0 0 ${W} 360`} width="100%" style={{ display: "block" }}>
      {/* CVE */}
      <rect x={modCx - 130} y={8} width={260} height={52} rx={5} fill="#FFFFFF" stroke={T.p0} strokeWidth="1" />
      <text x={modCx} y={28} textAnchor="middle" fontFamily={MONO} fontSize="13" fontWeight="600" fill={T.ink}>{w.cve}</text>
      <text x={modCx} y={46} textAnchor="middle" fontFamily={MONO} fontSize="11" fill={T.quiet}>
        {w.dep} {w.cur} → {w.fix}
      </text>

      <line x1={modCx} y1={60} x2={modCx} y2={84} stroke={T.quiet} strokeWidth="1.25" />
      <text x={modCx + 8} y={76} fontFamily={SANS} fontSize="10" fill={T.faint}>vulnerable dependency of</text>

      {/* shared module */}
      <rect x={modCx - 165} y={86} width={330} height={62} rx={5} fill={T.accentSoft} stroke={T.accent} strokeWidth="1.25" />
      <text x={modCx} y={107} textAnchor="middle" fontFamily={MONO} fontSize="13" fontWeight="600" fill={T.ink}>{w.module}</text>
      <text x={modCx} y={124} textAnchor="middle" fontFamily={SANS} fontSize="11" fill={T.quiet}>
        owned by {w.owner} · Wave 1 PR {w.wave1.pr}
      </text>
      <text x={modCx} y={139} textAnchor="middle" fontFamily={SANS} fontSize="11" fill={T.p1}>
        open {w.wave1.ageDays} days · unblocks everything below
      </text>

      {/* edges */}
      {cs.map((c, i) => {
        const cx = xs[i] + cw / 2;
        const excluded = c.state === "excluded";
        const stroke = excluded ? T.faint : REACH_STROKE[c.reach];
        return (
          <g key={c.repo}>
            <path d={`M ${modCx} 148 C ${modCx} 190, ${cx} 190, ${cx} 232`}
              fill="none" stroke={stroke}
              strokeWidth={c.reach === "true" ? 2 : 1.25}
              strokeDasharray={excluded ? "2 4" : c.reach === "unknown" ? "5 3" : "none"}
              opacity={excluded ? 0.5 : 1} />
            {excluded && (
              <>
                <line x1={cx - 6} y1={196} x2={cx + 6} y2={208} stroke={T.faint} strokeWidth="1.5" />
                <line x1={cx + 6} y1={196} x2={cx - 6} y2={208} stroke={T.faint} strokeWidth="1.5" />
              </>
            )}
          </g>
        );
      })}

      {/* consumers */}
      {cs.map((c, i) => {
        const excluded = c.state === "excluded";
        return (
          <g key={c.repo} style={{ cursor: c.fp ? "pointer" : "default" }}
            onClick={() => c.fp && go("finding", c.fp)}>
            <rect x={xs[i]} y={232} width={cw} height={72} rx={5}
              fill={excluded ? "#F7F8F9" : "#FFFFFF"}
              stroke={excluded ? T.rule : REACH_STROKE[c.reach]}
              strokeWidth={c.reach === "true" && !excluded ? 1.75 : 1}
              strokeDasharray={excluded ? "3 3" : "none"} />
            <text x={xs[i] + 10} y={251} fontFamily={MONO} fontSize="11.5" fontWeight="500"
              fill={excluded ? T.faint : T.ink}>{c.repo}</text>
            <text x={xs[i] + 10} y={267} fontFamily={SANS} fontSize="10" fill={T.quiet}>
              tier {c.tier} · common {c.ver.startsWith("replace") ? "replaced" : c.ver}
            </text>
            <text x={xs[i] + 10} y={283} fontFamily={SANS} fontSize="10"
              fill={excluded ? T.faint : REACH_STROKE[c.reach]}>
              {excluded ? "excluded from wave" : REACH_WORD[c.reach]}
            </text>
            <text x={xs[i] + 10} y={297} fontFamily={SANS} fontSize="10"
              fill={excluded ? T.faint : T.p1}>
              {excluded ? "needs manual fix" : "blocked until Wave 2"}
            </text>
          </g>
        );
      })}

      {/* legend */}
      <g transform="translate(12, 330)">
        <line x1={0} y1={-3} x2={26} y2={-3} stroke={T.p0} strokeWidth="2" />
        <text x={32} y={0} fontFamily={SANS} fontSize="10" fill={T.quiet}>reaches vulnerable code</text>
        <line x1={186} y1={-3} x2={212} y2={-3} stroke={T.p1} strokeWidth="1.25" strokeDasharray="5 3" />
        <text x={218} y={0} fontFamily={SANS} fontSize="10" fill={T.quiet}>reachability unknown</text>
        <line x1={358} y1={-3} x2={384} y2={-3} stroke={T.faint} strokeWidth="1.25" />
        <text x={390} y={0} fontFamily={SANS} fontSize="10" fill={T.quiet}>depends, does not reach</text>
        <line x1={548} y1={-3} x2={574} y2={-3} stroke={T.faint} strokeWidth="1.25" strokeDasharray="2 4" />
        <text x={580} y={0} fontFamily={SANS} fontSize="10" fill={T.quiet}>excluded</text>
      </g>
    </svg>
  );
}

function Waves({ go }) {
  return (
    <div className="flex flex-col gap-3">
      <div style={{ background: T.surface, border: `1px solid ${T.rule}`, borderRadius: 4, padding: "12px 14px", fontSize: 13, color: T.ink, lineHeight: 1.6, maxWidth: "82ch" }}>
        <strong>Blast radius through first-party modules.</strong> One vulnerability in a shared module
        is one defect that surfaces as many findings. This view shows how far each one reaches, which
        consumers actually execute the vulnerable path, and the single upstream action that clears all of them.
        Consumers are held rather than patched individually — five divergent manifests get reverted by the
        next <span style={{ fontFamily: MONO, fontSize: 12 }}>go mod tidy</span>.
      </div>

      {WAVES.map((w) => {
        const blocked = w.consumers.filter((c) => c.state === "blocked");
        const excluded = w.consumers.filter((c) => c.state === "excluded");
        const reaching = blocked.filter((c) => c.reach === "true");
        const t1reach = reaching.filter((c) => c.tier === 1);
        return (
          <Panel key={w.fp}>
            <Head right={
              <span style={{ fontSize: 11, color: T.p1 }}>
                Wave 1 open {w.wave1.ageDays} days · Wave 2 trigger: {w.trigger}
              </span>
            }>
              <span className="inline-flex items-center" style={{ gap: 8 }}>
                <Pri p={w.pri} />
                <span style={{ fontFamily: MONO }}>{w.cve}</span>
                <span style={{ fontWeight: 400, color: T.quiet }}>via {w.module}</span>
              </span>
            </Head>

            {/* blast radius metrics */}
            <div className="flex" style={{ padding: "12px 14px", gap: 34, flexWrap: "wrap", borderBottom: `1px solid ${T.ruleSoft}` }}>
              {[["Consumers", w.consumers.length, T.ink],
                ["Blocked", blocked.length, T.p1],
                ["Reach the vulnerable code", reaching.length, T.p0],
                ["…of those, tier 1", t1reach.length, T.p0],
                ["Excluded, manual", excluded.length, T.quiet]].map(([l, v, c]) => (
                <div key={l}>
                  <div style={{ fontSize: 11, color: T.quiet }}>{l}</div>
                  <div style={{ fontFamily: MONO, fontSize: 20, color: c }}>{v}</div>
                </div>
              ))}
              <div style={{ flex: 1, minWidth: 220, fontSize: 11, color: T.quiet, alignSelf: "flex-end", lineHeight: 1.5 }}>
                {reaching.length} of {w.consumers.length} consumers execute the vulnerable path.
                Dependency count alone overstates exposure.
              </div>
            </div>

            <div style={{ padding: "6px 8px 4px" }}>
              <BlastRadius w={w} go={go} />
            </div>

            <div style={{ padding: "10px 14px", borderTop: `1px solid ${T.ruleSoft}` }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: T.ink, marginBottom: 6 }}>What clears this</div>
              <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: T.quiet, lineHeight: 1.75 }}>
                <li>
                  Merge <span style={{ fontFamily: MONO, color: T.accent }}>{w.owner} {w.wave1.pr}</span> — bumps
                  {" "}<span style={{ fontFamily: MONO }}>{w.dep}</span> to {w.fix} in the shared module.
                </li>
                <li style={{ color: T.p1 }}>
                  <strong>Cut a tag.</strong> Wave 2 triggers on <span style={{ fontFamily: MONO }}>{w.trigger}</span>,
                  not on merge. A merged Wave 1 with no tag leaves every consumer blocked and the PR closed —
                  the most common way this stalls silently.
                </li>
                <li>
                  Wave 2 then opens deterministic bump PRs in {blocked.length} consumers. No agent, no review of logic,
                  just <span style={{ fontFamily: MONO, fontSize: 11 }}>go get · tidy · build · test</span>.
                </li>
                <li>
                  Handle <span style={{ fontFamily: MONO }}>{excluded[0]?.repo}</span> by hand — {excluded[0]?.why}.
                </li>
              </ol>
            </div>
          </Panel>
        );
      })}

      <Panel>
        <Head right={<span style={{ fontSize: 11, color: T.faint }}>standing exposure, independent of any current CVE</span>}>
          Module fan-out
        </Head>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ fontSize: 11, color: T.quiet }}>
              {["First-party module", "Owner", "Consumers", "Tier 1", "Version spread", "Active waves"].map((h, i) => (
                <th key={h} style={{ textAlign: i > 1 ? "right" : "left", padding: "6px 12px", fontWeight: 500, borderBottom: `1px solid ${T.ruleSoft}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12 }}>github.com/org/common</td>
              <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.accent }}>wanaware-common</td>
              {[4, 2].map((v, i) => (
                <td key={i} style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 12 }}>{v}</td>
              ))}
              <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 11, color: T.p1 }}>v1.3.9 – v1.4.1</td>
              <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 12 }}>1</td>
            </tr>
          </tbody>
        </table>
        <div style={{ padding: "10px 12px", fontSize: 11, color: T.quiet, lineHeight: 1.6, maxWidth: "80ch" }}>
          Fan-out is a standing property of the dependency graph, not something that appears when a CVE does.
          It answers the question before the incident: if this module has a vulnerability tomorrow, how far does it reach?
          Version spread matters too — consumers on different versions cannot all be bumped to one target in a single wave.
        </div>
      </Panel>
    </div>
  );
}

const GAPS = [
  {
    repo: "payments-web", blind: "total", tool: "all scanners", run: "S-001247",
    firstFailed: "S-001246", streak: 2, lastGood: "S-001245", daysBlind: 14,
    exit: "clone timed out after 300s",
    detail: "Repository is 4.2 GB. Full clone exceeds the worker timeout; history contains large binary assets.",
    lost: "Everything. No dependency scan, no SAST, no secret scan, no config scan.",
    stale: 26, action: "Enable partial clone (--filter=blob:none) or raise the worker timeout.",
    owner: "Platform", history: [1, 1, 1, 1, 1, 1, 0, 0],
  },
  {
    repo: "ops-tools", blind: "partial", tool: "govulncheck", run: "S-001247",
    firstFailed: "S-001247", streak: 1, lastGood: "S-001246", daysBlind: 7,
    exit: "exit 2 — build failure in ./cmd/legacy",
    detail: "Reachability analysis requires a compiling program. One module fails to build, so the whole invocation aborts.",
    lost: "Go dependency findings and all reachability analysis. gitleaks, trivy and gosec completed normally.",
    stale: 5, action: "Repair the ./cmd/legacy build, or exclude that module from scanning.",
    owner: "ops-tools CODEOWNERS", history: [1, 1, 1, 1, 1, 1, 1, 0],
  },
];

function CoverageStrip({ history }) {
  return (
    <span className="inline-flex items-center" style={{ gap: 3 }}>
      {history.map((ok, i) => (
        <span key={i} title={SWEEPS[i]?.id} style={{
          width: 16, height: 16, borderRadius: 2, display: "inline-block",
          background: ok ? "#E4EAE6" : T.p0,
          border: `1px solid ${ok ? "#CBD6CF" : T.p0}`,
        }} />
      ))}
    </span>
  );
}

const TEMPLATES = [
  { id: "fleet", name: "Fleet summary", audience: "Platform, security",
    what: "Headline counts and deltas, new and regressed findings, per-repository rollup, coverage gaps, cost.",
    rows: 312 },
  { id: "repo-digest", name: "Repository digest", audience: "Repository code owners",
    what: "One repository. Findings with age and SLA status, open pull requests, any coverage gap.",
    rows: 47, needsRepo: true },
  { id: "exec-summary", name: "Executive summary", audience: "Leadership",
    what: "Counts, trends, SLA posture, coverage percentage. No individual findings.", rows: 0 },
  { id: "audit-pack", name: "Audit evidence pack", audience: "External auditor",
    what: "Point-in-time full detail, scanner digest, tool versions, and coverage attestation including what was not scanned.",
    rows: 312, heavy: true },
  { id: "remediation-queue", name: "Remediation queue", audience: "Engineers",
    what: "Filtered working list ordered by priority then age.", rows: 125, usesFilter: true },
  { id: "first-party", name: "First-party exposure", audience: "Platform",
    what: "Blast radius, wave status, module fan-out, version spread.", rows: 5 },
  { id: "coverage-attestation", name: "Coverage attestation", audience: "Auditor, security",
    what: "Per repository: scanned or not, by which tools, last clean scan.", rows: 41 },
];

const ISSUED = [
  { id: "R-000042", template: "audit-pack", anchor: "S-001246", by: "@suparna",
    at: "27 Aug 2026 10:14 UTC", hash: "sha256:4b91c7…e02a", formats: ["pdf", "json"], redacted: 2 },
  { id: "R-000041", template: "exec-summary", anchor: "S-001246", by: "@suparna",
    at: "26 Aug 2026 09:02 UTC", hash: "sha256:1f38ab…77d1", formats: ["pdf"], redacted: 0 },
  { id: "R-000038", template: "repo-digest", anchor: "S-001245", by: "@jeff",
    at: "20 Aug 2026 16:40 UTC", hash: "sha256:c0d442…9b3e", formats: ["md"], redacted: 0,
    supersededBy: "R-000039" },
];

function Reports({ filters, scopeRun, go }) {
  const [tpl, setTpl] = useState("audit-pack");
  const t = TEMPLATES.find((x) => x.id === tpl);
  const [anchor, setAnchor] = useState(LATEST_SWEEP.id);
  const [fmt, setFmt] = useState("pdf");
  const filterCount = Object.values(filters).flat().length;

  const field = (label, node) => (
    <div className="flex" style={{ gap: 12, padding: "7px 0", alignItems: "flex-start" }}>
      <span style={{ fontSize: 11, color: T.quiet, width: 96, flexShrink: 0, paddingTop: 4 }}>{label}</span>
      <div style={{ flex: 1, minWidth: 0 }}>{node}</div>
    </div>
  );

  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <Head right={<span style={{ fontSize: 11, color: T.faint }}>anchored, immutable, hashed</span>}>
          Generate a report
        </Head>
        <div style={{ padding: "10px 14px" }}>
          {field("Template",
            <>
              <select value={tpl} onChange={(e) => setTpl(e.target.value)}
                style={{ fontSize: 13, padding: "5px 7px", border: `1px solid ${T.rule}`, borderRadius: 3, background: T.surface, color: T.ink, minWidth: 280 }}>
                {TEMPLATES.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
              </select>
              <div style={{ fontSize: 12, color: T.quiet, marginTop: 6, lineHeight: 1.55, maxWidth: "74ch" }}>
                <span style={{ color: T.ink }}>For {t.audience}.</span> {t.what}
              </div>
            </>)}

          {field("Anchor",
            <>
              <select value={anchor} onChange={(e) => setAnchor(e.target.value)}
                style={{ fontFamily: MONO, fontSize: 12, padding: "5px 7px", border: `1px solid ${T.rule}`, borderRadius: 3, background: T.surface, color: T.ink, minWidth: 280 }}>
                {[...SWEEPS].reverse().map((r) => <option key={r.id} value={r.id}>{r.id} · {r.time}</option>)}
              </select>
              <div style={{ fontSize: 11, color: T.p1, marginTop: 6, lineHeight: 1.55, maxWidth: "74ch" }}>
                Reports anchor to a completed run. There is no option for current state — a report generated
                from live data cannot be regenerated tomorrow, so it cannot be cited or verified.
              </div>
            </>)}

          {t.usesFilter && field("Filter",
            <div style={{ fontSize: 12, color: T.ink }}>
              {filterCount > 0
                ? <>Carried from the explorer: <span style={{ fontFamily: MONO, fontSize: 11, color: T.accent }}>
                    {Object.entries(filters).map(([k, v]) => `${k}:${v.join("|")}`).join("  ")}</span></>
                : <span style={{ color: T.quiet }}>No filter set. Set one in Findings to narrow this report.</span>}
            </div>)}

          {field("Format",
            <div className="flex" style={{ gap: 6 }}>
              {["pdf", "md", "csv", "xlsx", "json"].map((f) => (
                <button key={f} onClick={() => setFmt(f)}
                  style={{
                    fontFamily: MONO, fontSize: 12, padding: "3px 10px", borderRadius: 3, cursor: "pointer",
                    border: `1px solid ${fmt === f ? T.accent : T.rule}`,
                    background: fmt === f ? T.accentSoft : T.surface,
                    color: fmt === f ? T.accent : T.ink,
                  }}>{f}</button>
              ))}
            </div>)}

          {field("Size",
            <div style={{ fontSize: 12, color: t.heavy ? T.p1 : T.quiet }}>
              ~{t.rows} records{t.heavy && " · large, allow up to two minutes"}
              {t.rows > 1000 && " · exceeds the 1,000-record limit; narrow the filter"}
            </div>)}

          {field("Visibility",
            <div style={{ fontSize: 12, color: T.quiet, lineHeight: 1.55, maxWidth: "74ch" }}>
              Secret findings are excluded from every template. Where a recipient's access is narrower than
              yours, the report is redacted at generation and states how many records were withheld.
            </div>)}

          <div style={{ paddingTop: 10, borderTop: `1px solid ${T.ruleSoft}`, marginTop: 6 }}>
            <button style={{
              fontSize: 13, padding: "7px 16px", borderRadius: 3, border: "none",
              background: T.accent, color: "#FFFFFF", cursor: "pointer",
            }}>Generate {t.name} · {anchor} · {fmt}</button>
            <span style={{ fontSize: 11, color: T.faint, marginLeft: 12 }}>
              Issues a new immutable report with its own identifier and content hash.
            </span>
          </div>
        </div>
      </Panel>

      <Panel>
        <Head right={<span style={{ fontFamily: MONO, fontSize: 12, color: T.quiet }}>{ISSUED.length}</span>}>
          Issued reports
        </Head>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ fontSize: 11, color: T.quiet }}>
              {["Report", "Template", "Anchor", "Issued", "By", "Content hash", "Formats", ""].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "6px 12px", fontWeight: 500, borderBottom: `1px solid ${T.ruleSoft}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ISSUED.map((r) => (
              <tr key={r.id}>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, fontWeight: 600, color: r.supersededBy ? T.faint : T.accent, whiteSpace: "nowrap" }}>
                  {r.id}
                </td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontSize: 12, color: T.ink }}>
                  {TEMPLATES.find((x) => x.id === r.template)?.name}
                </td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, color: T.quiet }}>{r.anchor}</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontSize: 11, color: T.quiet, whiteSpace: "nowrap" }}>{r.at}</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, color: T.quiet }}>{r.by}</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, color: T.faint, whiteSpace: "nowrap" }}>{r.hash} ⧉</td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}>
                  <span className="flex" style={{ gap: 5 }}>
                    {r.formats.map((f) => (
                      <span key={f} style={{ fontFamily: MONO, fontSize: 10, padding: "1px 5px", borderRadius: 2, border: `1px solid ${T.rule}`, color: T.accent }}>{f}</span>
                    ))}
                  </span>
                </td>
                <td style={{ padding: "7px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontSize: 11, whiteSpace: "nowrap" }}>
                  {r.supersededBy
                    ? <span style={{ color: T.faint }}>superseded by {r.supersededBy}</span>
                    : r.redacted > 0
                      ? <span style={{ color: T.p1 }}>{r.redacted} records withheld</span>
                      : <span style={{ color: T.faint }}>complete</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ padding: "10px 12px", fontSize: 11, color: T.quiet, lineHeight: 1.6, maxWidth: "88ch" }}>
          Reports are immutable once issued. A correction is a new report that supersedes the old one; neither
          is deleted. The content hash lets a copy found in an email thread months later be checked against
          the original — which is most of why an issued report is worth more than a screenshot.
        </div>
      </Panel>
    </div>
  );
}

function Gaps({ go }) {
  const totalStale = GAPS.reduce((a, g) => a + g.stale, 0);
  const worst = Math.max(...GAPS.map((g) => g.daysBlind));
  return (
    <div className="flex flex-col gap-3">
      <div style={{ background: "#FBF4EC", border: `1px solid ${T.p1}`, borderRadius: 4, padding: "12px 14px" }}>
        <div style={{ fontSize: 13, color: T.ink, lineHeight: 1.6, maxWidth: "84ch" }}>
          <strong>{GAPS.length} repositories with reduced coverage in S-001247.</strong> One has been
          blind for {worst} days. {totalStale} findings were not re-observed as a result — they carry the
          <span style={{ color: T.p1 }}> ▪ </span>marker in finding tables and must not be read as resolved.
          A repository that failed to scan and a repository with no findings are indistinguishable in every
          aggregate on the run overview.
        </div>
      </div>

      {GAPS.map((g) => (
        <Panel key={g.repo + g.tool}>
          <div className="flex items-center justify-between" style={{ padding: "10px 14px", borderBottom: `1px solid ${T.ruleSoft}`, gap: 12, flexWrap: "wrap" }}>
            <div className="flex items-center" style={{ gap: 10, flexWrap: "wrap" }}>
              <button onClick={() => go("repo", g.repo)}
                style={{ fontFamily: MONO, fontSize: 14, color: T.accent, background: "none", border: "none", padding: 0, cursor: "pointer" }}>
                {g.repo}
              </button>
              <span style={{
                fontSize: 11, padding: "2px 7px", borderRadius: 3,
                background: g.blind === "total" ? T.p0 : "#FBF4EC",
                color: g.blind === "total" ? "#FFFFFF" : T.p1,
                border: `1px solid ${g.blind === "total" ? T.p0 : T.p1}`,
              }}>
                {g.blind === "total" ? "no coverage" : "partial coverage"}
              </span>
              <span style={{ fontFamily: MONO, fontSize: 11, padding: "1px 6px", borderRadius: 3, background: "#EEF1F4", color: T.quiet }}>
                {g.tool}
              </span>
            </div>
            <div className="flex items-center" style={{ gap: 7 }}>
              <span style={{ fontFamily: MONO, fontSize: 12, fontWeight: 600, color: KIND_INK.sweep, background: KIND_TINT.sweep, padding: "1px 6px", borderRadius: 3 }}>
                {g.run}
              </span>
              <span style={{ fontSize: 12, color: T.quiet }}>{LATEST_SWEEP.time}</span>
            </div>
          </div>

          <div className="flex" style={{ padding: "12px 14px", gap: 32, flexWrap: "wrap", borderBottom: `1px solid ${T.ruleSoft}` }}>
            {[["Consecutive failures", `${g.streak}`, g.streak > 1 ? T.p0 : T.ink],
              ["Days without data", `${g.daysBlind}`, g.daysBlind > 7 ? T.p0 : T.p1],
              ["Last clean scan", g.lastGood, T.ink],
              ["Findings not re-observed", `${g.stale}`, T.p1]].map(([l, v, c]) => (
              <div key={l}>
                <div style={{ fontSize: 11, color: T.quiet }}>{l}</div>
                <div style={{ fontFamily: MONO, fontSize: 17, color: c }}>{v}</div>
              </div>
            ))}
            <div style={{ marginLeft: "auto" }}>
              <div style={{ fontSize: 11, color: T.quiet, marginBottom: 4 }}>
                Coverage, {SWEEPS[0].id.slice(-4)} → {LATEST_SWEEP.id.slice(-4)}
              </div>
              <CoverageStrip history={g.history} />
            </div>
          </div>

          <div style={{ padding: "12px 14px", display: "grid", gap: 10 }}>
            {[["Failure", <span key="f"><span style={{ fontFamily: MONO, fontSize: 12, color: T.p0 }}>{g.exit}</span> — {g.detail}</span>],
              ["What we lost", g.lost],
              ["Action", g.action],
              ["Owner", g.owner]].map(([l, v]) => (
              <div key={l} className="flex" style={{ gap: 12 }}>
                <span style={{ fontSize: 11, color: T.quiet, width: 108, flexShrink: 0, paddingTop: 2 }}>{l}</span>
                <span style={{ fontSize: 12.5, color: T.ink, lineHeight: 1.55, maxWidth: "76ch" }}>{v}</span>
              </div>
            ))}
            <div className="flex" style={{ gap: 12, paddingTop: 6, borderTop: `1px solid ${T.ruleSoft}` }}>
              <span style={{ fontSize: 11, color: T.quiet, width: 108, flexShrink: 0 }} />
              <button onClick={() => go("findings", { repo: [g.repo], _scope: "open" })}
                style={{ fontSize: 12, color: T.accent, background: "none", border: "none", padding: 0, cursor: "pointer" }}>
                View the {g.stale} findings last seen in {g.lastGood} →
              </button>
            </div>
          </div>
        </Panel>
      ))}

      <Panel>
        <Head right={<span style={{ fontSize: 11, color: T.faint }}>filled = clean, red = failed</span>}>
          Fleet coverage history
        </Head>
        <div style={{ padding: "12px 14px" }}>
          {REPOS.map((r) => {
            const g = GAPS.find((x) => x.repo === r.name);
            const hist = g ? g.history : [1, 1, 1, 1, 1, 1, 1, 1];
            return (
              <div key={r.name} className="flex items-center" style={{ gap: 12, padding: "3px 0" }}>
                <span style={{ fontFamily: MONO, fontSize: 12, color: T.ink, width: 170 }}>{r.name}</span>
                <CoverageStrip history={hist} />
                <span style={{ fontSize: 11, color: g ? T.p0 : T.faint, marginLeft: 8 }}>
                  {g ? `${g.streak} consecutive` : "complete"}
                </span>
              </div>
            );
          })}
          <div style={{ fontSize: 11, color: T.quiet, marginTop: 12, lineHeight: 1.6, maxWidth: "84ch" }}>
            Coverage trending down is a more serious signal than findings trending up. A repository that
            stops scanning removes itself from every count on the run overview, so the numbers improve
            while the risk does not. Read this strip before reading any headline figure.
          </div>
        </div>
      </Panel>
    </div>
  );
}

function RepoFindingTable({ items, tier, go }) {
  const order = { P0: 0, P1: 1, P2: 2, P3: 3 };
  const rows = [...items].sort((a, b) => order[a.pri] - order[b.pri] || ageDays(b) - ageDays(a));
  const th = (h, right) => (
    <th key={h} style={{ textAlign: right ? "right" : "left", padding: "6px 12px", fontWeight: 500, borderBottom: `1px solid ${T.ruleSoft}` }}>{h}</th>
  );
  return (
    <>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ fontSize: 11, color: T.quiet }}>
            {th("")}{th("Identifier")}{th("Component")}
            {th("Seen (sweep #)")}{th("Age", true)}{th("SLA", true)}{th("State")}
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => {
            const sla = slaStatus(f, tier);
            const age = ageDays(f);
            return (
              <tr key={f.fp} onClick={() => go("finding", f.fp)} style={{ cursor: "pointer" }}>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}><Pri p={f.pri} /></td>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.ink }}>
                  {f.id}{f.aliases?.length > 0 && <span style={{ color: T.faint }}> +{f.aliases.length}</span>}
                </td>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 12, color: T.quiet, maxWidth: 230 }} className="truncate">
                  {f.component}{f.fn ? ` · ${f.fn}()` : ""}
                </td>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, fontFamily: MONO, fontSize: 11, whiteSpace: "nowrap" }}>
                  <span style={{ color: T.faint }}>{sweepFor(f.firstSeen).id.slice(-4)}</span>
                  <span style={{ color: "#C2C9D0" }}> → </span>
                  <span style={{ color: notReobserved(f) ? T.p1 : T.ink }}>{sweepFor(f.lastSeen).id.slice(-4)}</span>
                  {notReobserved(f) && <span style={{ color: T.p1 }}> ▪</span>}
                </td>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 12, color: RESOLVED.includes(f.state) ? T.faint : T.ink, whiteSpace: "nowrap" }}>
                  {age}d
                </td>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}`, textAlign: "right", fontFamily: MONO, fontSize: 11, color: sla.color, fontWeight: sla.bold ? 600 : 400, whiteSpace: "nowrap" }}>
                  {sla.text}
                </td>
                <td style={{ padding: "6px 12px", borderBottom: `1px solid ${T.ruleSoft}` }}>
                  <span style={stateStyle(f.state)}>{STATE_LABEL[f.state]}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div style={{ padding: "8px 12px", fontSize: 11, color: T.faint, lineHeight: 1.6, maxWidth: "88ch" }}>
        Age runs from first detection, not from triage or assignment, and stops at verification — not at merge.
        SLA is measured against the tier {tier} window for each priority
        (P0 {SLA[tier].P0}d · P1 {SLA[tier].P1}d · P2 {SLA[tier].P2}d · P3 {SLA[tier].P3}d, placeholder pending VM-OQ-02).
        The clock pauses where no upstream fix exists — those cannot breach, because there is nothing to ship.
      </div>
    </>
  );
}

function RepoView({ name, go }) {
  const r = REPOS.find((x) => x.name === name);
  const roll = ROLLUP.find((x) => x.repo === name);
  const fs = FINDINGS.filter((f) => f.repo === name);
  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <div style={{ padding: "14px 16px" }}>
          <div style={{ fontFamily: MONO, fontSize: 18, color: T.ink }}>{name}</div>
          <div style={{ fontSize: 12, color: T.quiet, marginTop: 6 }}>
            Tier {r.tier} · {r.lang} · {r.topology} module · owners {r.owners.join(", ")} · last scanned 2 Sep 03:00
          </div>
          {!r.tests && (
            <div style={{ marginTop: 10, padding: "8px 10px", background: "#FBF4EC", border: `1px solid ${T.p1}`, borderRadius: 3, fontSize: 12, color: T.ink }}>
              <strong style={{ color: T.p1 }}>No executable test suite.</strong> Agentic source fixes are not permitted here; findings route to tickets instead.
            </div>
          )}
          {r.firstParty && (
            <div style={{ marginTop: 10, fontSize: 12, color: T.quiet }}>
              Publishes first-party module <span style={{ fontFamily: MONO, color: T.ink }}>{r.firstParty}</span> · 4 consumers
            </div>
          )}
        </div>
        {roll && (
          <div className="flex" style={{ padding: "12px 16px", gap: 40, borderTop: `1px solid ${T.ruleSoft}` }}>
            {[["Found", roll.found], ["Fixed", roll.fixed], ["Open", roll.open], ["Open PRs", roll.prs]].map(([l, v]) => (
              <div key={l}>
                <div style={{ fontSize: 11, color: T.quiet }}>{l}</div>
                <div style={{ fontFamily: MONO, fontSize: 18, color: T.ink }}>{v}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>
      <Panel>
        <Head right={
          <span style={{ fontSize: 11, color: T.quiet }}>
            {fs.filter((f) => !RESOLVED.includes(f.state) && slaStatus(f, r.tier).text.startsWith("breach")).length} past SLA
            <span style={{ color: T.faint }}> · {fs.length} total</span>
          </span>
        }>Findings</Head>
        <RepoFindingTable items={fs} tier={r.tier} go={go} />
      </Panel>
    </div>
  );
}

/* ============================================================
   SHELL
   ============================================================ */
export default function App() {
  const [view, setView] = useState("current");
  const [arg, setArg] = useState(null);
  const [filters, setFilters] = useState({});
  const [q, setQ] = useState("");
  const [scope, setScope] = useState("open");
  const [scopeRun, setScopeRun] = useState("S-001247");

  const go = (v, a) => {
    if (v === "findings" && a && typeof a === "object") {
      const { _scope, _run, ...f } = a;
      setFilters(f); setQ("");
      if (_scope) setScope(_scope);
      if (_run) setScopeRun(_run);
    }
    setView(v); setArg(typeof a === "string" ? a : null);
  };

  const url = useMemo(() => {
    if (view === "findings") {
      const parts = [scope === "run" ? `run=${scopeRun}` : `scope=${scope}`];
      parts.push(...Object.entries(filters).map(([k, vs]) => `${k}=${vs.join(",")}`));
      if (q) parts.push(`q=${encodeURIComponent(q)}`);
      return "/findings?" + parts.join("&");
    }
    if (view === "finding") return `/findings/${arg}`;
    if (view === "repo") return `/repos/${arg}`;
    if (view === "snapshot") return `/runs/${arg}`;
    if (view === "runs") return "/runs";
    if (view === "waves") return "/waves";
    if (view === "gaps") return "/gaps";
    if (view === "reports") return "/reports";
    return "/runs/latest";
  }, [view, arg, filters, q, scope, scopeRun]);

  const NAV = [
    ["current", "Current"], ["runs", "Runs"], ["findings", "Findings"],
    ["repos", "Repositories"], ["waves", "Waves"], ["gaps", "Gaps"], ["reports", "Reports"],
  ];

  return (
    <div style={{ background: T.ground, minHeight: "100vh", fontFamily: SANS, color: T.ink }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
        *{box-sizing:border-box} table tbody tr:hover{background:#F6F8FA}
        button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid ${T.accent};outline-offset:1px}`}</style>

      <div className="flex" style={{ minHeight: "100vh" }}>
        <nav style={{ width: 172, background: T.surface, borderRight: `1px solid ${T.rule}`, flexShrink: 0 }}>
          <div style={{ padding: "16px 14px 12px" }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: T.ink }}>Vulnerability</div>
            <div style={{ fontSize: 13, color: T.quiet }}>report browser</div>
          </div>
          {NAV.map(([k, l]) => {
            const on = view === k || (k === "current" && view === "snapshot") ||
              (k === "findings" && view === "finding") || (k === "repos" && view === "repo");
            return (
              <button key={k} onClick={() => go(k)} className="flex items-center w-full text-left"
                style={{
                  padding: "7px 14px", fontSize: 13, border: "none", cursor: "pointer",
                  background: on ? T.accentSoft : "transparent",
                  color: on ? T.accent : T.ink,
                  borderLeft: on ? `2px solid ${T.accent}` : "2px solid transparent",
                }}>
                {l}
                {k === "gaps" && <span style={{ marginLeft: "auto", fontFamily: MONO, fontSize: 11, color: T.p1 }}>2</span>}
                {k === "waves" && <span style={{ marginLeft: "auto", fontFamily: MONO, fontSize: 11, color: T.quiet }}>1</span>}
              </button>
            );
          })}
          <div style={{ padding: "16px 14px", fontSize: 11, color: T.faint, lineHeight: 1.5 }}>
            Simulated data. Read-only prototype per VM-UI v0.1.
          </div>
        </nav>

        <main className="flex flex-col" style={{ flex: 1, minWidth: 0 }}>
          <div style={{ padding: "7px 16px", borderBottom: `1px solid ${T.rule}`, background: T.surface }}>
            <span style={{ fontFamily: MONO, fontSize: 11, color: T.faint }}>
              claude-vuln.internal<span style={{ color: T.accent }}>{url}</span>
            </span>
          </div>
          <div style={{ padding: 16, flex: 1 }}>
            {view === "current" && <RunOverview go={go} />}
            {view === "snapshot" && <Snapshot runId={arg} go={go} />}
            {view === "runs" && <Runs go={go} />}
            {view === "findings" && <Explorer filters={filters} setFilters={setFilters} q={q} setQ={setQ}
              scope={scope} setScope={setScope} scopeRun={scopeRun} setScopeRun={setScopeRun} go={go} />}
            {view === "finding" && <FindingDetail fp={arg} go={go} />}
            {view === "waves" && <Waves go={go} />}
            {view === "gaps" && <Gaps go={go} />}
            {view === "reports" && <Reports filters={filters} scopeRun={scopeRun} go={go} />}
            {view === "repos" && (
              <Panel>
                <Head>Repositories</Head>
                <div>{REPOS.map((r) => (
                  <button key={r.name} onClick={() => go("repo", r.name)} className="flex items-center w-full text-left"
                    style={{ padding: "9px 14px", border: "none", borderBottom: `1px solid ${T.ruleSoft}`, background: "none", cursor: "pointer", gap: 12 }}>
                    <span style={{ fontFamily: MONO, fontSize: 13, color: T.accent, width: 180 }}>{r.name}</span>
                    <span style={{ fontSize: 12, color: T.quiet }}>Tier {r.tier} · {r.lang}</span>
                    {!r.tests && <span style={{ fontSize: 11, color: T.p1, marginLeft: "auto" }}>no test suite</span>}
                  </button>
                ))}</div>
              </Panel>
            )}
            {view === "repo" && <RepoView name={arg} go={go} />}
          </div>
        </main>
      </div>
    </div>
  );
}
