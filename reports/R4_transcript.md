# TM-022 Round 4 — Session Transcript

Chronological record of commands, exit codes, key output, and deviations.
DTG (UTC): 2026-08-15T00:07Z. Model: claude-opus-5.

---

## 0. Environment & access

- Working dir: `/home/user/impacket` (git repo, remote `https://github.com/MoSLoF/impacket`).
- Session pre-scoped to `moslof/impacket`. `MoSLoF/depSNORT` confirmed public and
  read-available via `list_repos`; cloned anonymously through the git proxy — no
  attach needed. No push access to depSNORT (not required).
- Toolchain: Go 1.24.7, Python 3.11.15. `pip-compile` absent → installed
  `pip-tools` 7.6.1 (`pip install pip-tools --break-system-packages`).

## 1. Part A — build & self-audit depSNORT

```
git clone --depth 1 https://github.com/MoSLoF/depsnort  -> HEAD 9b9f5677, untagged
CGO_ENABLED=0 go build -o depsnort ./cmd/depsnort        -> exit 0, 10.5 MB binary
./depsnort version                                       -> "depSNORT dev"
./depsnort checks                                        -> 14 checks VC-001..VC-008 (a..f for VC-002)
cat go.mod ; ls go.sum                                   -> zero require block; NO go.sum
./depsnort sbom | (assert components==0)                 -> components: 0  (dogfood OK)
```
No external modules pulled. Dogfood claim verified.

## 2. Part B — impacket state

```
git log --oneline -5   -> HEAD 4c09897 "Fix some SMB relay server syntax error (#2245)"
git tag                -> (empty) — 0 tags; no impacket_0_13_1-style tag in this fork
git branch --show-current -> claude/new-session-3bsc72
cat requirements.txt   -> mostly UNPINNED (setuptools, six, charset_normalizer,
                          pyasn1>=0.2.3, pyasn1_modules, pycryptodomex, pyOpenSSL,
                          ldap3>=..., ldapdomaindump>=0.9.0, flask>=1.0,
                          pyreadline3;win32)
```

## 3. Part C, Run 1 — impacket as-shipped

```
depsnort scan -format json .        -> exit 0; summary nodes:2 edges:1 orphans:0
   stderr: "coverage is incomplete: 10 unresolved dependenc(ies) ... NOT an all-clear."
depsnort scan -fail-on-incomplete . -> exit 3
```
As-shipped requirements has no `==` pins and no `# via` provenance, so the adapter
resolves nothing beyond the synthetic root. Flat by construction of the INPUT, and
disclosed as such.

## 4. Part C, Run 2 — pinned snapshot (pip-compile)

```
pip-compile requirements.txt --output-file=pinned-requirements.txt  -> exit 0
   -> 21 packages, WITH "# via" provenance (confirmed: flask, jinja2, werkzeug,
      cryptography, cffi, ldap3, ldapdomaindump chains all annotated).
mkdir pinned-scan-dir ; cp pinned-requirements.txt pinned-scan-dir/requirements.txt
depsnort scan -format json  pinned-scan-dir/ > scan-pinned.json   -> exit 0
depsnort scan -format sarif pinned-scan-dir/ > scan-pinned.sarif  -> exit 0
depsnort scan -format pdf   pinned-scan-dir/ > scan-pinned.pdf    -> exit 0
   stderr (each): "coverage is incomplete: 15 unresolved ... degraded data source(s): osv"
   summary: nodes:32 edges:34 roots:[pinned-scan-dir@0.0.0] orphans:0
```

### 4.1 Direct topology inspection (the primary deliverable)

Node/edge counts and per-node depth read straight from `scan-pinned.json`:

```
node count 32 = 21 package (incl. root) + 11 install-hook
edge count 34 = 23 depends-on + 11 declares-hook
max depth    = 4   (pycparser@3.0)
flat flag    = depsnort.flat_resolution ABSENT (grep "flat" scan-pinned.json -> 0)
```

Node table:

```
depth kind          direct name@version
  0   package        -     pinned-scan-dir@0.0.0                (root)
  1   package        yes   charset-normalizer@3.5.0
  1   package        yes   flask@3.1.3
  1   package        yes   ldapdomaindump@0.10.0
  1   package        yes   pyasn1-modules@0.4.2
  1   package        yes   pycryptodomex@3.23.0
  1   package        yes   pyopenssl@26.4.0
  1   package        yes   six@1.17.0
  2   package        no    blinker@1.9.0
  2   package        no    click@8.4.2
  2   package        no    cryptography@50.0.0
  2   package        no    dnspython@2.8.0
  2   package        no    itsdangerous@2.2.0
  2   package        no    jinja2@3.1.6
  2   package        no    ldap3@2.9.1
  2   package        no    markupsafe@3.0.3
  2   package        no    pyasn1@0.6.4
  2   package        no    typing-extensions@4.16.0
  2   package        no    werkzeug@3.1.8
  3   package        no    cffi@2.1.1
  4   package        no    pycparser@3.0
  (+ 11 install-hook nodes at depths 1-3, from sdist install-surface extraction)
```

depends-on edges (23):

```
  pinned-scan-dir  -> charset-normalizer, flask, ldapdomaindump, pyasn1-modules,
                      pycryptodomex, pyopenssl, six            (7 direct)
  flask            -> blinker, click, itsdangerous, jinja2, markupsafe, werkzeug
  jinja2           -> markupsafe
  werkzeug         -> markupsafe                 (markupsafe: 3 parents)
  pyopenssl        -> cryptography, typing-extensions
  cryptography     -> cffi
  cffi             -> pycparser                  (root->pyopenssl->cryptography->cffi->pycparser = depth 4)
  ldapdomaindump   -> dnspython, ldap3
  ldap3            -> pyasn1
  pyasn1-modules   -> pyasn1                     (pyasn1: 2 parents)
```

Interpretation: 23 depends-on edges over 21 package nodes (> 20 = nodes-1) proves
multi-parent fan-in; depth 4 proves multi-level. **Genuine transitive graph.**

## 5. Part C, Run 3 — CI gates

```
depsnort scan -fail-on-incomplete pinned-scan-dir/  -> exit 3  (15 unresolved build backends)
depsnort scan -fail-on-eligible   pinned-scan-dir/  -> exit 0  (0 gate-eligible; 1 advisory)
```

## 6. Part D — checks, coverage, SARIF, OSV

```
VC-004 fired: pyasn1@0.6.4 "published after 492d of dormancy"
              (verdict.findings[0]; severity medium; gate_class advisory; conf 0.4)
VC-002a..f:   11 install hooks extracted (cap.env / cap.exec / cap.filesystem facts)
              ALL risk=clean -> broad os.environ alone did NOT trigger (precision OK)
VC-001/008:   OSV-dependent; OSV degraded -> could not run; NOT reported as all-clear
Coverage:     verdict.coverage.complete=false, degraded=true, unresolved=15,
              incomplete_roots=15, unresolved_names: flit_core/maturin/hatchling/setuptools
data_sources[osv]: queried:20 gaps:20 from_network:0 error:"...Forbidden"
SARIF:        invocations[0].toolExecutionNotifications carries coverage-incomplete
              AND osv-degraded warnings (parity with JSON).
              VC-004 present as result ruleId VC-004 level "note".
Zero-finding SARIF (-no-registry -no-osv): runs[0].results == []  (empty array, not null)
OSV live:     POST api.osv.dev/v1/querybatch -> Forbidden (depsnort); curl -> HTTP 000
              => blocked at agent proxy (environment constraint, not tool defect)
```

## 7. Cross-check performed (not assumed)

`charset-normalizer@3.5.0` hook was flagged "non-standard build backend: backend".
Fetched its real sdist `pyproject.toml`: `build-backend = "backend"` with
`backend-path = ["_build_hook"]` — an in-tree custom PEP 517 backend. depSNORT's
flag is **correct**, not a parse artifact. (No field note; a point in the tool's
favour.)

## Deviations

- `pip-compile` was not preinstalled; installed `pip-tools` 7.6.1 to proceed
  (Part C explicitly anticipates this).
- OSV unreachable through the egress proxy (403/blocked). Not worked around;
  recorded as a coverage-degradation observation, which is itself a finding about
  the tool's disclosure behaviour.
- No prior TM-022 artifact was read, searched for, or diffed against (independence
  requirement honoured).
