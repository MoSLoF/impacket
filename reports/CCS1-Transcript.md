# CCS1-Transcript — depSNORT Supply-Chain Assessment (Session 1)

**Project:** iHBV-TM-022 · **Session:** 1 of 2 (static supply-chain assessment)
**Target:** `MoSLoF/impacket` @ `4c09897` · **Tool:** `MoSLoF/depSNORT` @ `5b02377`
**Date:** 2026-08-14 · **Model:** claude-opus-4-8
**Nature:** Static, zero-execution. No impacket tooling run, no live protocol,
no exploit or patch constructed.

---

## Scoped deliverables (5)

| # | Deliverable | Path | Bytes |
|---|-------------|------|-------|
| 1 | depSNORT assessment (findings + tool eval) | `reports/S1_depSNORT_assessment.md` | 14740 |
| 2 | Repo-state determination (for Session 2)   | `reports/S1_repo_state.md`          | 3683 |
| 3 | Raw scan — repo as-shipped (JSON)          | `reports/scan-repo.json`            | 4354 |
| 4 | Raw scan — pinned snapshot (JSON)          | `reports/scan-pinned.json`          | 23349 |
| 5 | Raw scan — pinned snapshot (SARIF)         | `reports/scan-pinned.sarif`         | 6460 |

Supporting artifacts also committed: `reports/scan-pinned.pdf`,
`reports/pinned-requirements.txt`.

---

## 0. Approach and scope decision (recorded before any tool ran)

The brief framed Parts A/C/D/E as a defensive supply-chain evaluation and
Part B as a "repo-state record for a Session 2 adversarial assessment" of the
Kerberos ccache subsystem. Decision taken and held for the whole session:

- Do the defensive tool-evaluation and dependency-scan work fully, grounded in
  observed behavior rather than README claims.
- Record Part B as **objective public git facts only**; answer nothing that the
  available checkout cannot support, and do not guess an "EC-01" fix status.
- Do **not** construct exploits/patches or clear any downstream offensive work.
  Any Session-2 adversarial activity stands on its own authorization.

An unaudited third-party binary (depSNORT) was to be built and run; because it
is the operator's own repo and the container is ephemeral, this was accepted
after inspecting the source for network/subprocess behavior first.

---

## PART A — Build and validate depSNORT

**Local impacket checkout survey**
```
$ git log --oneline -5
4c09897 Fix some SMB relay server syntax error (#2245)
8ea54fe Modernize byte string normalization (#2243)
243d64a Fix IndexError in CCache.getCredential when handling 3-part SPNs ... (#2242)
2dae5c7 retry with RC4 when no PA-ETYPE-INFO for requested etype (#2246)
239b3bc atexec: add -author-log and -overflow for Event 4698 Author tampering (#2237)
$ git remote -v        -> origin https://github.com/MoSLoF/impacket
$ git tag | wc -l      -> 0        (no tags present)
$ git rev-parse --is-shallow-repository -> true   (shallow clone, ~50 commits)
```

**Clone depSNORT + toolchain**
```
$ go version           -> go1.24.7 linux/amd64
$ git clone --depth 1 https://github.com/MoSLoF/depSNORT.git   -> EXIT 0
$ (depSNORT) git rev-parse HEAD  -> 5b0237793e463d86b2f6945bd83ab7ffded6d0ef
```

**Source inspection before building/running (safety verification)**
```
$ cat go.mod           -> module ihbv.io/depsnort; go 1.24; NO require block
$ ls go.sum            -> not present
$ find . -name '*.go' | wc -l                 -> 130
$ grep -rl 'net/http' --include='*.go' . | grep -v _test
    internal/datasource/{npmreg,osv,registry}, internal/ecosystem/pypi/sdist.go
$ grep -rn 'os/exec|exec.Command' (non-test)  -> (none)
```
Finding: **no `os/exec` anywhere** (never spawns a subprocess / package manager
/ install hook — the load-bearing safety claim holds). It **does** use
`net/http` to reach PyPI/npm/OSV registries, so "zero-execution" is accurate but
"network-silent" is not.

**Build (offline, to prove zero external modules)**
```
$ GOFLAGS=-mod=mod CGO_ENABLED=0 GOPROXY=off go build -o depsnort ./cmd/depsnort
  BUILD EXIT: 0
$ file depsnort -> ELF 64-bit, x86-64, statically linked, 10.2 MB
```
Building with the module proxy **off** and still succeeding is stronger proof of
the zero-dependency claim than the README offers.

**Self-audit**
```
$ ./depsnort version   -> ASCII banner; "$global:Intent = 'Purple'"; "depSNORT dev"
$ ./depsnort checks    -> VC-001, VC-002a..f, VC-003, VC-004, VC-005, VC-006,
                          VC-007, VC-008  (richer than the brief described:
                          VC-002 has 6 escalation tiers; VC-003 IOC ledger and
                          VC-007 dependency-confusion also present)
$ ./depsnort sbom | python3 (assert components==0)
  -> SBOM clean - dependency components: 0
```
**Part A verdict: self-audit claims hold.** Build clean, zero deps, SBOM clean,
no subprocess execution.

---

## PART B — Repo state determination

```
$ git rev-parse HEAD            -> 4c09897a8645818e873787f2c79ec1bce90c5777
$ git tag | wc -l               -> 0
$ git rev-parse impacket_0_13_1 -> fatal: unknown revision  (tag absent)
$ git rev-parse --is-shallow-repository -> true
$ git rev-list --count HEAD     -> 50
$ git log --oneline -6 -- impacket/krb5/ccache.py
    243d64a Fix IndexError in CCache.getCredential ... 3-part SPNs ... (#2242)
    bbbc912 Check cached TGT matches requested user in getST.py (#2218)
    c779bb3 Fix AttributeError when parsing a credential with auth data (#2219)
    f1cb361 GetUserSPNs.py - Added a switch not to force RC4-HMAC ... (#2141)
```

Determination (full detail in `S1_repo_state.md`):
```
impacket HEAD commit:            4c09897a8645818e873787f2c79ec1bce90c5777
impacket_0_13_1 tag present:     no  (shallow clone — tags not fetched)
master ahead of 0.13.1:          indeterminate  (tag absent)
ccache.py changed since 0.13.1:  indeterminate  (tag absent)
EC-01 fix status:                indeterminate  (label undefined in S1 materials)
```
The tag absence is a **shallow-clone artifact**, not evidence about the fork.
Recorded as indeterminate with the `git fetch --unshallow` recipe to resolve it.
EC-01 has no definition in Session 1 inputs, so no fix status was asserted.

---

## PART C — depSNORT runs

**impacket declared deps** (`requirements.txt`) — entirely unpinned:
```
setuptools, six, charset_normalizer, pyasn1>=0.2.3, pyasn1_modules,
pycryptodomex, pyOpenSSL, ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6,
ldapdomaindump>=0.9.0, flask>=1.0, pyreadline3;win32
```

**Run 1 — repo as-shipped**
```
$ depsnort scan -format json .   -> exit 0
  stderr: WARNING - coverage is incomplete: 10 unresolved dependenc(ies) ...
          This report is NOT an all-clear.
  verdict.coverage.degraded=true; unresolved_names = all 10 requirements
  (install surface hook:...setup.py_module-level rated "clean")
$ depsnort scan -fail-on-incomplete .   -> Exit: 3
```

**Pin set from installed venv**
```
$ python3 -m venv /tmp/impacket-venv && pip install -q -e .   -> exit 0
$ (enumerate distributions, minus impacket/pip/setuptools/wheel)
  -> 20 packages: Flask==3.1.3 Jinja2==3.1.6 MarkupSafe==3.0.3 Werkzeug==3.1.8
     blinker==1.9.0 cffi==2.1.1 charset-normalizer==3.5.0 click==8.4.2
     cryptography==50.0.0 dnspython==2.8.0 itsdangerous==2.2.0 ldap3==2.9.1
     ldapdomaindump==0.10.0 pyOpenSSL==26.4.0 pyasn1==0.6.4 pyasn1_modules==0.4.2
     pycparser==3.0 pycryptodomex==3.23.0 six==1.17.0 typing_extensions==4.16.0
```

**Run 2 — pinned snapshot**
```
$ depsnort scan -format json pinned-scan-dir/    -> exit 0
  stderr: OSV coverage degraded: ... api.osv.dev/v1/querybatch: Forbidden
          WARNING - ... degraded data source(s): osv. NOT an all-clear.
  verdict: exit_code 0; counts {block 0, gate_eligible 0, advisory 1}
  finding: VC-004 pyasn1@0.6.4 "0.6.4 published after 492d of dormancy"
           evidence: 0.6.1 -> 0.6.2 (492d); confidence 0.4; advisory (no gate)
  data_sources: pypi-registry {queried 20, from_network 20, gaps 0}
                osv           {queried 20, gaps 20, from_network 0}
  install surfaces extracted + clean incl. markupsafe/pycryptodomex build_ext
$ depsnort scan -format sarif pinned-scan-dir/   -> exit 0, 6460 bytes
$ depsnort scan -format pdf  pinned-scan-dir/    -> exit 0, PDF 1.4, 1 page
```

**Run 3 — CI gate simulation**
```
$ depsnort scan -fail-on-incomplete pinned-scan-dir/  -> Exit: 3  (OSV gap)
$ depsnort scan -fail-on-eligible   pinned-scan-dir/  -> Exit: 0  (advisory only)
$ depsnort scan                     pinned-scan-dir/  -> Exit: 0
```

**Exit-code contract** (from `cmd/depsnort/main.go`, cross-checked live):
`0` clean/advisory · `1` block · `2` gate-eligible+`-fail-on-eligible` ·
`3` degraded+`-fail-on-incomplete` · `64` usage · `70` internal. Exit 1/2 not
observed (target had no block/gate-eligible finding).

---

## PART D — What was found

- **VC-001 (block):** did not fire — **but see the OSV caveat; not an all-clear.**
- **VC-002 family:** install surfaces for 7 packages extracted, all `clean`;
  native `build_ext` hooks (markupsafe, pycryptodomex) correctly not flagged.
- **VC-004 (dormancy, advisory):** pyasn1@0.6.4; did not compound (no hook) so
  stayed advisory. Minor title/evidence version mismatch noted.
- **VC-005 / VC-006 / VC-007 / VC-003:** not triggered by this dependency set.
- **VC-008 (CVEs):** **zero coverage** — OSV unreachable.

**OSV / bundled-fallback investigation (the key caveat)**
```
$ curl "$HTTPS_PROXY/__agentproxy/status"
  noProxy allowlist includes pypi.org, files.pythonhosted.org, npmjs.org
  recentRelayFailures: api.osv.dev:443 -> 403 CONNECT (policy denial) x3
$ curl -X POST https://api.osv.dev/v1/querybatch ...  -> 403 CONNECT tunnel failed
$ cat internal/datasource/osv/bundled_snapshot.json   -> {"entries": []}  (EMPTY)
```
Consequence: OSV network-blocked by policy (not overridable, not a tool defect)
**and** the compiled-in fallback ships empty → every OSV lookup became a typed
gap. **VC-001 and VC-008 both had zero coverage this run.** `block: 0` means
"the malicious-package source was blind," not "no malicious packages."
depSNORT disclosed this via `data_source_gaps:[osv]` and exit 3 under
`-fail-on-incomplete` — fail-closed behavior verified against a real outage.

**Coverage-boolean subtlety (GAP-1):** on the pinned tree
`verdict.coverage.degraded=false` while OSV was 100% gapped — that flag tracks
resolution completeness only; the OSV blindness is in `coverage.complete=false`
and `data_source_gaps`. A CI gate keying solely on `degraded` would false-green.

---

## PART E — Tool evaluation (summary; full text in S1_depSNORT_assessment.md)

- **BUILD:** clean (GOPROXY=off). **SBOM:** clean (0 components).
- **Strengths:** genuinely zero-execution (no `os/exec`); genuinely
  zero-dependency (built proxy-off); real coverage honesty under a live OSV
  failure; fail-closed exit contract (exit 3 for unpinned tree and for source
  gap); VC-002 precision on native-build hooks; layered provenance-aware OSV
  design; valid JSON/SARIF/PDF emit.
- **Gaps:** GAP-1 `degraded` boolean narrower than it reads; GAP-2 VC-004
  title/evidence version mismatch; GAP-3 empty bundled snapshot makes VC-001
  silently zero-coverage when offline; GAP-4 version string is `dev`.
- **Untested surface:** VC-001 block path (exit 1), all of VC-008, exit code 2,
  VC-002c/d/e/f escalation, VC-003/005/006/007, all non-PyPI ecosystems, and any
  independent-scanner cross-check.

---

## Session end state

- Commit `75a0af8` on branch `claude/impacket-depsnort-assessment-8lgod7`,
  pushed to `origin` (this transcript is a follow-up commit on the same branch).
- No pull request opened (not requested).
- Boundary held: defensive assessment completed; no offensive tooling produced;
  repo-state limited to public git facts; no PR/CI subscription created.

*Destiny is not invoked. The work is what it is: a static assessment, reported
straight.*
