# S1 — depSNORT Supply-Chain Assessment of impacket

**Project:** iHBV-TM-022
**Tool:** depSNORT @ `5b02377` (built from `MoSLoF/depSNORT`, reported version string `dev`)
**Target:** `MoSLoF/impacket` @ `4c09897` (shallow clone)
**Date:** 2026-08-14
**Assessment type:** Static supply-chain / dependency-tree, zero package execution
**Prepared by:** Session 1

---

## 0. Headline

- depSNORT builds with **zero third-party modules** (verified with `GOPROXY=off`)
  and self-audits to a **clean SBOM** (0 dependency components). The "unaudited
  tool auditing supply chains" concern does not apply to this build.
- **No block-class (VC-001) finding fired.** However — see §3 — this is **not**
  an all-clear on malicious packages, because the known-malicious data source
  (OSV) was **network-blocked in this environment** and the compiled-in fallback
  dataset ships **empty** in this build. The malicious-package check was
  effectively **blind**, and depSNORT correctly said so.
- One real finding on the pinned tree: **VC-004 dormancy advisory on
  `pyasn1==0.6.4`** (advisory only, does not gate).
- The tool's **coverage-honesty and fail-closed exit-code behavior are its
  strongest observed properties** and both were verified against a real failure
  (blocked OSV), not just asserted.

---

## 1. Findings

### FINDING: DEP-01 — Dependency-resolution coverage is degraded on the repo as-shipped
```
TOOL/CHECK:   depSNORT (coverage engine, design decision D-01)
SEVERITY:     informational (degraded coverage, correctly disclosed)
EXIT CODE:    0 (plain scan) / 3 (with -fail-on-incomplete)
DESCRIPTION:  impacket's requirements.txt is entirely unpinned (lower-bounds and
              exclusions only, no == pins). depSNORT refuses to resolve unpinned
              specifiers and reports all 10 direct requirements as unresolved:
              charset_normalizer, flask, ldap3, ldapdomaindump, pyOpenSSL,
              pyasn1, pyasn1_modules, pycryptodomex, setuptools, six.
              Both stderr and verdict.coverage.degraded=true announce this;
              the report is explicitly labelled "NOT an all-clear".
PACKAGE(S):   all 10 direct requirements (unresolved)
OPERATIONAL:  Expected and correct — this is D-01 behaviour, not a tool failure.
              An operator cannot get real coverage from the repo as-shipped; a
              resolved/pinned snapshot is required (see Run 2). A CI gate should
              run -fail-on-incomplete so an unpinned tree fails closed (exit 3).
```

### FINDING: DEP-02 — VC-004 dormancy advisory on pyasn1==0.6.4
```
TOOL/CHECK:   depSNORT VC-004 (weather / dormancy)
SEVERITY:     advisory
EXIT CODE:    0 (advisory does not gate; -fail-on-eligible also returned 0)
DESCRIPTION:  On the pinned tree, pyasn1 node marked "warned". Finding title:
              "0.6.4 published after 492d of dormancy". Evidence string cites the
              gap 0.6.1 -> 0.6.2 (492d, 2024-09-10 -> 2026-01-16). confidence 0.4,
              recency_decay ~0.198, score ~0.0397. No install hook on pyasn1, so
              per the VC-004 rule it does NOT escalate to gate-eligible.
PACKAGE(S):   pyasn1==0.6.4
OPERATIONAL:  Advisory only — worth a human glance at the pyasn1 publishing
              account/release provenance, but not a gate. Note the title/evidence
              provenance nit in §4 (GAP-2): the headline version (0.6.4) and the
              evidenced dormancy gap (0.6.1->0.6.2) don't line up, so treat the
              specific version string in the title with mild caution.
```

### FINDING: DEP-03 — Malicious-package (VC-001) determination was NOT possible in this run
```
TOOL/CHECK:   depSNORT VC-001 (known-compromise / block) + VC-008 (CVE)
SEVERITY:     informational (coverage gap — safety-critical to record)
EXIT CODE:    0 (plain) / 3 (with -fail-on-incomplete)
DESCRIPTION:  All 20 OSV lookups failed: the agent network policy returns a hard
              403 CONNECT denial for api.osv.dev (not in the proxy allowlist;
              pypi.org IS, which is why registry metadata resolved fine). The
              binary's compiled-in fallback advisory dataset (bundled_snapshot.json)
              ships EMPTY in this build ("entries": []). With no cache, no network,
              and an empty bundle, every OSV coordinate became a typed gap:
              data_sources.osv = {queried:20, gaps:20, from_network:0, from_cache:0}
              and verdict.coverage.data_source_gaps = ["osv"].
PACKAGE(S):   all 20 resolved packages (no OSV-backed determination for any)
OPERATIONAL:  CRITICAL READING CAVEAT. "block: 0" here means "the known-malicious
              source was unreachable", NOT "no known-malicious packages present".
              VC-001's "if it fires, stop" safety net was blind this run. Before
              trusting any all-clear, re-run with api.osv.dev reachable (or import
              a snapshot via -osv-snapshot / -osv-export from a networked host).
              The tool disclosed this correctly; the gap is environmental, not a
              tool defect.
```

### FINDING: DEP-04 — Install-surface (VC-002 family) extracted and clean, incl. native-build hooks
```
TOOL/CHECK:   depSNORT VC-002a..f (install-hook capability analysis)
SEVERITY:     informational (no VC-002 finding; precision observation)
EXIT CODE:    0
DESCRIPTION:  On the pinned tree depSNORT statically extracted install surfaces
              from setup.py / pyproject.toml for cffi, charset-normalizer, ldap3,
              markupsafe, pycryptodomex, pyopenssl, six — including the
              cmdclass.build_ext hooks on markupsafe and pycryptodomex (native
              C-extension builds). Every extracted hook was rated "clean". No
              VC-002 finding of any tier fired.
PACKAGE(S):   cffi, charset-normalizer, ldap3, markupsafe, pycryptodomex,
              pyopenssl, six (install surfaces), all clean
OPERATIONAL:  Strong precision signal: native-extension build_ext cmdclass is
              exactly the shape a naive hook scanner false-positives on, and
              depSNORT did not. Consistent with the design note that broad
              os.environ access is deliberately NOT a signal — only named
              secrets + egress escalate. No hook here reached named credentials
              or network egress, so nothing crossed into VC-002c/d.
```

---

## 2. Run log (exit codes are findings, recorded explicitly)

| Run | Command | Exit | Meaning |
|-----|---------|------|---------|
| 1  | `scan -format json .` (repo as-shipped) | **0** | plain scan; advisory/none, but coverage degraded (10 unresolved) |
| 1b | `scan -fail-on-incomplete .` | **3** | degraded resolution → fail closed |
| 2  | `scan -format json pinned-scan-dir/` | **0** | 1 advisory (VC-004); OSV gapped |
| 2  | `scan -format sarif pinned-scan-dir/` | **0** | valid SARIF, 6460 bytes |
| 2  | `scan -format pdf pinned-scan-dir/` | **0** | valid PDF 1.4, 1 page, 6292 bytes |
| 3  | `scan -fail-on-incomplete pinned-scan-dir/` | **3** | OSV data-source gap alone trips incompleteness |
| 3  | `scan -fail-on-eligible pinned-scan-dir/` | **0** | only finding is advisory → no gate |

Exit-code contract (from `cmd/depsnort/main.go` header, cross-checked against
observed behavior): `0` clean/advisory-only · `1` block-class present · `2`
gate-eligible present with `-fail-on-eligible` · `3` degraded/incomplete with
`-fail-on-incomplete` · `64` usage · `70` internal error. **Exit 1 and exit 2
were not observed** (target had no block-class or gate-eligible finding) — see
UNTESTED SURFACE.

---

## 3. Coverage disclosure — did the tool tell us when it couldn't check?

Yes, consistently, and this is the single most important behavior verified:

- **Repo as-shipped:** stderr `WARNING - coverage is incomplete: 10 unresolved
  dependenc(ies) ... This report is NOT an all-clear.` plus
  `verdict.coverage.degraded=true` and a full `unresolved_names` list.
- **Pinned tree:** stderr `OSV coverage degraded: ... "https://api.osv.dev/v1/querybatch": Forbidden`
  and `... degraded data source(s): osv. This report is NOT an all-clear.`,
  with `verdict.coverage.data_source_gaps=["osv"]` and per-source
  `osv.gaps=20`.

**Subtlety worth flagging to any CI integrator (GAP-1):** on the pinned tree
`verdict.coverage.degraded` is **`false`** even though OSV was fully gapped —
that boolean tracks *dependency-resolution* completeness only. The OSV blindness
lives in `verdict.coverage.complete=false` and `data_source_gaps`. A gate that
keys solely on `degraded` would wrongly treat an OSV-blind scan as clean. Key on
`complete` **and** `data_source_gaps`, or just use the `-fail-on-incomplete`
exit code (which does account for source gaps → exit 3).

---

## 4. Tool evaluation

```
TOOL:            depSNORT @ 5b02377 (version string "dev")
BUILD:           clean — CGO_ENABLED=0 GOPROXY=off go build succeeded; static
                 ELF, 10.2 MB; no go.sum, no require block; nothing fetched.
SBOM CLEAN:      yes — 0 dependency components (verified programmatically).
FINDINGS ON TARGET (pinned): 1 advisory (VC-004 pyasn1). 0 block, 0 gate-eligible.
                 CVE/VC-008 and VC-001 uncovered this run (OSV blocked, empty bundle).
COVERAGE:        degraded — resolution complete on pinned tree (0 unresolved), but
                 OSV data source fully gapped (20/20). Repo as-shipped: 10/10
                 unresolved (unpinned). Both states correctly disclosed.
```

**STRENGTHS (grounded in observation):**
- **Genuinely zero-execution.** No `os/exec` anywhere in the source (verified by
  grep). It reads lockfiles/manifests and statically parses install surfaces; it
  never runs a package manager or install hook. This is the load-bearing safety
  claim and it holds.
- **Genuinely zero-dependency.** Built with the module proxy *off* and still
  compiled — the strongest possible proof there is no external module supply
  chain. SBOM self-audit reports 0 components.
- **Coverage honesty is real, not cosmetic.** Under a live failure (blocked OSV)
  it degraded and labelled the report "NOT an all-clear" on both stderr and in
  structured JSON, rather than emitting a silent green.
- **Fail-closed exit contract.** `-fail-on-incomplete` returned 3 for *both* an
  unpinned tree and an OSV data-source gap — a properly configured CI gate
  cannot be tricked into passing an under-covered scan.
- **VC-002 precision.** Correctly did not flag native-extension `build_ext`
  cmdclass hooks (markupsafe, pycryptodomex) — the classic false-positive shape.
- **Layered, provenance-aware OSV design.** cache → network → bundled → typed
  gap, with a deliberate rule that a bundled-sourced hit is *not* presented as a
  live check. Rich flag surface (`-offline`, `-osv-snapshot`, `-osv-export`,
  `-no-osv-bundled`) supports true air-gapped operation.
- **Multi-format emit works.** JSON, SARIF, and PDF all produced valid,
  well-formed output in one pass.

**GAPS (specific, reproducible, with suggested fix):**
- **GAP-1 — `degraded` boolean is narrower than it reads.** On the pinned tree
  `coverage.degraded=false` while OSV was 100% gapped. A naive integrator keying
  on `degraded` gets a false green. *Fix:* rename to `resolution_degraded`, or
  add a top-level `coverage.all_clear=false` that is the logical AND of
  resolution completeness and zero data-source gaps.
- **GAP-2 — VC-004 title/evidence mismatch.** Finding title says
  "0.6.4 published after 492d of dormancy" but the evidence gap is
  `0.6.1 -> 0.6.2`. The headline version and the evidenced transition disagree.
  *Fix:* derive the title's version from the same transition the evidence cites.
- **GAP-3 — empty bundled fallback in the shipped build.** `bundled_snapshot.json`
  is `{"entries": []}`, so the "air-gapped still gets known-malicious coverage"
  story is inert unless the operator runs `scripts/refresh-bundled-snapshot.sh`
  (which needs network) first. In an OSV-blocked environment this makes VC-001
  silently zero-coverage. *Fix:* ship a non-empty curated MAL snapshot, and/or
  have the tool warn at startup when the bundle is empty AND network is
  unreachable.
- **GAP-4 — version string is `dev`.** No embedded build/version identity; the
  SBOM and reports say `dev`. *Fix:* stamp a real version/commit via ldflags at
  release so findings are attributable to a tool revision.

**UNTESTED SURFACE (honest list — what this session did NOT exercise):**
- **VC-001 block path (exit 1)** — never fired; no known-malicious package was
  present *and* the source that would detect one was unreachable. Block behavior
  is therefore unverified end-to-end on a real target here.
- **VC-008 (CVE) entirely** — OSV blocked; zero CVE data obtained. No CVE
  count / severity distribution could be recorded.
- **Exit code 2 (gate-eligible)** — no gate-eligible finding occurred on this
  target, so `-fail-on-eligible` returning non-zero was not observed live.
- **VC-002c/d/e/f** (creds/egress/decode-exec/remote-fetch-exec) — no hook on
  this tree reached those tiers, so only the "clean" path of VC-002 was
  exercised, not its escalation.
- **VC-003 (IOC ledger), VC-005 (release burst), VC-006 (typosquat),
  VC-007 (dependency confusion)** — not triggered by this dependency set;
  `-ioc` / `-internal-names` / `-internal-scopes` inputs were not supplied.
- **Any non-PyPI ecosystem** — impacket is pure-Python; npm/cargo/rubygems/
  composer/go registries were present but idle (`queried:0`).
- **Cross-check against a second scanner** — findings were not corroborated by
  an independent tool.

---

## 5. Recommendation for a real operator using depSNORT on impacket

1. Do not run depSNORT against the repo as-shipped for a pass/fail decision —
   the unpinned tree yields degraded coverage by design. Resolve to a pinned
   snapshot first (as done in Run 2).
2. In CI, always pass `-fail-on-incomplete` so both unpinned trees and
   data-source outages fail closed (exit 3) instead of emitting a soft green.
3. **This run's OSV blindness must be lifted before any all-clear is credible.**
   Either allowlist `api.osv.dev` in the network policy, or bootstrap
   `-osv-snapshot` from a networked host via `-osv-export`. Until then, VC-001
   and VC-008 have zero coverage regardless of a `0 block` verdict.
4. Treat the pyasn1 VC-004 dormancy advisory as a provenance glance, not a
   blocker.
```

---

*Static assessment only. No impacket tooling was executed, no live protocol was
exercised, and no exploit or patch was constructed. Raw artifacts:
`scan-repo.json`, `scan-pinned.json`, `scan-pinned.sarif`, `scan-pinned.pdf`,
`pinned-requirements.txt`.*
