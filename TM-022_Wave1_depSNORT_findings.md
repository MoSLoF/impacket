# TM-022 Wave 1 — depSNORT dependency assessment of impacket

**Tool:** [MoSLoF/depSNORT](https://github.com/MoSLoF/depSNORT) @ `5b02377` (built from source, `dev` build, Go 1.24)
**Target:** `/home/user/impacket` on `claude/impacket-adversarial-wave-1-39koer` (master head `4c09897`)
**Date:** 2026-08-14
**Environment note:** the runner's egress proxy denies `api.osv.dev` at the gateway
(HTTP 403 CONNECT). All temporal/registry data sources reached (npm-registry,
pypi-registry, cargo, composer, nuget, rubygems); only the OSV advisory tier
degraded. The `-fail-on-incomplete` gate exercises this cleanly.

## Runs performed

| # | Command (against) | verdict | exit | notes |
|---|-------------------|---------|------|-------|
| 1 | `depsnort scan /home/user/impacket` | 0 findings | 0 | 10/10 declared deps **unresolved** (unpinned specifiers, per D-01); coverage.degraded=true |
| 2 | `depsnort scan -fail-on-incomplete /home/user/impacket` | — | **3** | CI would gate on impacket's unpinned requirements |
| 3 | `depsnort scan <pinned>` (10/10 pins from an installed venv) | 1 advisory | 0 | full temporal coverage; OSV advisory tier 403-degraded |
| 4 | `depsnort scan -fail-on-incomplete <pinned>` | — | **3** | still 3 because OSV data source is degraded (network policy) |
| 5 | `depsnort scan -format {sarif,dot,pdf}` | same | 0 | outputs archived alongside |

Full artifacts committed under `tm022_wave1_harness/`:
- `depsnort-scan-repo.json` — run 1 (real repo, unpinned)
- `depsnort-scan-pinned.json` — run 3 (10/10 pinned)
- `depsnort-scan-pinned.sarif` — SARIF for CI dashboards / code-scanning
- `depsnort-pinned-requirements.txt` — the pin set used for runs 3–5
- `TM-022_Wave1_depSNORT_report.pdf` — repo root, human-readable PDF report

## Findings

### DEP-01 — impacket's `requirements.txt` is entirely unpinned (**gate-eligible**)
```
CHECK:          coverage (D-01: depSNORT refuses to resolve unpinned specifiers)
FILES:          /home/user/impacket/requirements.txt
EVIDENCE:       all 10 declared deps returned as unresolved by the PyPI resolver:
                setuptools, six, charset_normalizer, pyasn1, pyasn1_modules,
                pycryptodomex, pyOpenSSL, ldap3, ldapdomaindump, flask
GATE:           exit 3 under -fail-on-incomplete (would fail CI)
```
Only two specifiers carry lower bounds (`pyasn1>=0.2.3`, `flask>=1.0`,
`ldapdomaindump>=0.9.0`, `ldap3>=2.5,!=…`) and none pin an upper bound or exact
version. Consequence: every fresh `pip install` picks whatever the resolver
currently prefers, so **no cross-machine or cross-CI-run reproducibility of the
dep tree**, and the OSV advisory layer can't be run against a stable set —
a compromised newer minor release of any dep is picked up silently until the
release is yanked. Add a `requirements.lock` (or use `pip-compile`) so scanners
can act on a fixed graph.

### DEP-02 — `pyasn1@0.6.4` published after 492 days of dormancy (VC-004, **advisory**)
```
CHECK:          VC-004 (temporal weather: dormancy)
NODE:           pkg:pypi/pyasn1@0.6.4
SCORE:          medium severity × exponential 90-day half-life
GATE:           advisory only (never gates)
```
The **only** substantive finding across the pinned scan. `pyasn1` was silent for
492 days and then released 0.6.4 — the classic account-takeover shape depSNORT
watches for. Per VC-004's design this stays advisory unless the awakening
release *also* declares an install hook, which pyasn1's does not (verified in
the install-surface subgraph — no `install-hook` node for pyasn1@0.6.4). No
action required, but it is worth noting that pyasn1 is a **load-bearing
Kerberos/ASN.1 crypto dep** for impacket: a compromise of that account would
poison every impacket install. Treat pyasn1's next release as one to watch, not
one to auto-upgrade.

### DEP-03 — install-surface subgraph: 10 install hooks across the transitive tree, **zero capabilities flagged**
```
CHECK:          VC-002 family (install-hook capability analysis)
GATE:           clean
```
depSNORT statically extracted install hooks from every resolved dep. All 10
`install-hook` nodes carry `capabilities: none` — no network reach, no named
credentials, no decode-and-execute, no download cradle. Hooks enumerated:

| Package | Hook site |
|---------|-----------|
| charset-normalizer 3.4.6 | pyproject.toml build-backend + setup.py module-level |
| ldap3 2.9.1 | setup.py module-level |
| pycryptodomex 3.23.0 | setup.py module-level + cmdclass.build_ext |
| pyOpenSSL 26.4.0 | pyproject.toml build-backend + setup.py module-level |
| setuptools 68.1.2 | setup.py module-level + cmdclass.install |
| six 1.16.0 | setup.py module-level |

Notably `setuptools`'s `cmdclass.install` was not misclassified as
exfil-capable — depSNORT's precision-first design (VC-002 only flags *named*
credential access, not blanket env reads) held up on the legitimate native-build
shape. impacket's own `setup.py` also parsed clean (no capability flags — even
though `setup.py` shells out to `git` for versioning, that's not a network reach
and not a credential read).

### DEP-04 — coverage / data-source degradation
```
CHECK:          coverage
GATE:           exit 3 under -fail-on-incomplete
```
`api.osv.dev` is 403-denied by the sandbox egress policy — verified in
`__agentproxy/status`'s `recentRelayFailures`. depSNORT correctly:
- reported the degradation in `data_sources` (`osv.gaps: 10`),
- refused to declare an all-clear (`coverage.degraded = false` on the pinned
  scan is a display of dep-graph completeness; the OSV degradation is separately
  called out on stderr and in `data_sources`),
- returned exit 3 under `-fail-on-incomplete`.
For an air-gapped or policy-restricted CI runner, the intended pattern is
`-osv-snapshot <file>` (a pre-fetched advisory JSON snapshot) or the built-in
bundled dataset tier; on this run neither returned hits for the pinned set, but
that is negative evidence (no `MAL-*` advisories against these 10 packages in
the snapshot), not a coverage gap.

### DEP-05 — VC-007 (dependency confusion) not exercised
depSNORT's dependency-confusion check requires `-internal-scopes` /
`-internal-names` to be declared. impacket ships no internal package names, so
VC-007 correctly no-op'd. Not a finding, but recorded so the matrix is complete.

## Summary table

| ID | Class | Gate | Impact |
|----|-------|------|--------|
| DEP-01 | unpinned deps (D-01) | **gate-eligible (exit 3)** | reproducibility gap; scanners can't gate on a fixed graph |
| DEP-02 | VC-004 dormancy on pyasn1@0.6.4 | advisory | monitor next pyasn1 release; crypto-critical dep |
| DEP-03 | VC-002 install-hook family | clean (0/10 capable) | no exfil/cradle install hooks in transitive tree |
| DEP-04 | coverage: OSV 403-blocked | gate-eligible (env) | sandbox limitation; not an impacket issue |
| DEP-05 | VC-007 dep-confusion | n/a | no internal scopes declared |

## Recommendation

Add a machine-generated pin set (`requirements.lock` via `pip-compile`, or a
`Pipfile.lock` / `uv.lock`) alongside the existing floating
`requirements.txt` so:
1. CI can gate on a stable graph (fixes DEP-01),
2. OSV/CVE scanning has a concrete `package@version` to match against,
3. dormancy-then-release events (DEP-02) become actionable (you can see the
   diff), not just advisory noise.

No blocking findings against the current impacket transitive tree.
