# TM-022 Round 4 — Full-Scope Session Transcript

Complete chronological record of the session: access, build, inspection, runs,
analysis, reporting, and delivery. Every tool call and its material result is
summarized in order. DTG (UTC) 2026-08-15T00:07Z. Model: claude-opus-5.
Independence requirement honoured throughout — no prior TM-022 artifact was
searched for, read, or diffed against.

---

## Phase 0 — Task intake

- Input: prompt file `4cdbbcf0-claudecodeprompt...depsnortdepthvalidation.md`
  (TM-022 Round 4, Session 1). Read in full.
- Objective parsed: determine by DIRECT graph inspection whether depSNORT's
  dependency resolution produces genuine multi-level structure or a flat star;
  secondary VC-001..VC-008 / coverage / SARIF / exit-code / OSV checks.
- Scope confirmed: static analysis only; no impacket execution; depSNORT +
  impacket dependency tree only.

## Phase 1 — Environment & repo access

| Step | Tool | Result |
|---|---|---|
| impacket git state | `Bash git log/tag/rev-parse` | HEAD `4c09897`, 0 tags, branch `claude/new-session-3bsc72`, remote `github.com/MoSLoF/impacket` |
| toolchain | `Bash` | Go 1.24.7, Python 3.11.15, `pip-compile` ABSENT |
| repo availability | `list_repos(depSNORT/moslof)` | `MoSLoF/depSNORT` public, read-available |
| add depSNORT | `add_repo(MoSLoF/depSNORT, read)` | anonymous git-proxy read available; no attach needed |
| clone | `Bash git clone --depth 1` | depSNORT HEAD `9b9f5677`, untagged |

Access model note: session was pre-scoped to `moslof/impacket`; depSNORT was
readable via the proxy (public repo) without attachment. No push access to
depSNORT (not required). No blind bare-URL clone-for-push attempted.

## Phase 2 — Part A: build & self-audit depSNORT

| Step | Command | Result |
|---|---|---|
| dependency check | `cat go.mod; ls go.sum` | zero `require`; NO `go.sum` (std-lib only) |
| build | `CGO_ENABLED=0 go build -o depsnort ./cmd/depsnort` | exit 0, 10.5 MB static binary |
| version | `./depsnort version` | `depSNORT dev` |
| checks | `./depsnort checks` | 14 checks VC-001..VC-008 (VC-002 a–f) |
| dogfood | `./depsnort sbom \| assert components==0` | components: 0 — dogfood holds |

Decision recorded before running: the tool is std-lib-only, self-audits clean,
and runs in an ephemeral sandbox → building and running it is low-risk and the
assessment is legitimate defensive supply-chain work. Proceeded.

## Phase 3 — Source inspection (grounding the topology question in code)

Read to understand HOW edges are built (so the later output could be interpreted,
not guessed):
- `internal/graph/graph.go` — Node has `Depth`; typed `depends-on` edges;
  first-write-wins node dedupe; `Orphans()` resolver-health metric.
- `internal/ecosystem/pypi/pypi.go` — `parseRequirements()` parses pip-compile
  `# via <parent>` comments into `depends-on` edges (lines 264–283); sets
  `AttrFlatResolution` ONLY when NO line carries provenance (line 307–313);
  only `==` pins are treated as resolved.
- `internal/graph/coverage.go` — flag constants: `depsnort.flat_resolution`,
  `depsnort.unresolved`, `depsnort.unresolved_count`.

Conclusion from code: multi-level capability EXISTS and is provenance-driven.
The mission still requires proving it from actual output — done in Phase 5.

## Phase 4 — Part B: impacket state

`requirements.txt` is mostly UNPINNED (loose specifiers `>=`, or bare names):
setuptools, six, charset_normalizer, pyasn1>=0.2.3, pyasn1_modules,
pycryptodomex, pyOpenSSL, ldap3>=..., ldapdomaindump>=0.9.0, flask>=1.0,
pyreadline3;win32. No `==` pins, no `# via` provenance.

## Phase 5 — Part C: depSNORT runs

**Run 1 — impacket as-shipped**
```
scan -format json .        -> exit 0; nodes:2 edges:1; "10 unresolved ... NOT an all-clear"
scan -fail-on-incomplete . -> exit 3
```

**Setup for Run 2** — `pip install pip-tools --break-system-packages` (7.6.1);
`pip-compile requirements.txt -o pinned-requirements.txt` (exit 0, network to
PyPI OK). Confirmed `# via` annotations present. Copied into `pinned-scan-dir/`.

**Run 2 — pinned snapshot**
```
scan -format json  pinned-scan-dir/  -> exit 0; nodes:32 edges:34
scan -format sarif pinned-scan-dir/  -> exit 0
scan -format pdf   pinned-scan-dir/  -> exit 0
stderr: "15 unresolved ... degraded data source(s): osv"
```

**Direct topology inspection** (Python over `scan-pinned.json`): node/depth table,
23 depends-on edges, multi-parent fan-in, max depth 4. → GENUINE MULTI-LEVEL.
Full tables in `R4_transcript.md` / `R4_depSNORT_assessment.md`.

**Run 3 — CI gates**
```
scan -fail-on-incomplete pinned-scan-dir/  -> exit 3
scan -fail-on-eligible   pinned-scan-dir/  -> exit 0
```

## Phase 6 — Part D: checks / coverage / SARIF / OSV

- Findings: VC-004 dormancy on `pyasn1@0.6.4` (only firing check). Verdict node
  map: `pyasn1` "warned", all else "clean".
- VC-002: 11 install hooks extracted from live sdists; ALL clean despite
  `cap.env/cap.exec/cap.filesystem` → precision holds (broad env ≠ signal).
- Coverage disclosed via stderr, JSON `verdict.coverage`, `data_sources[osv].error`,
  SARIF `toolExecutionNotifications`, exit 3.
- SARIF parity confirmed; zero-finding SARIF (`-no-registry -no-osv`) →
  `results: []` (empty array, not null).
- OSV: `POST api.osv.dev` → Forbidden; direct `curl` → HTTP 000 → blocked at
  egress proxy (environment constraint). Tool reported `queried:20 gaps:20
  from_network:0` + explicit error; no false all-clear.

## Phase 7 — Verification detour (avoided a false field note)

`charset-normalizer@3.5.0` hook flagged "non-standard build backend: backend".
Fetched its real sdist `pyproject.toml` via PyPI JSON API → `build-backend =
"backend"`, `backend-path = ["_build_hook"]` (in-tree PEP 517 backend). depSNORT
flag is CORRECT. Not a field note.

## Phase 8 — Reporting & delivery

| Artifact | Path |
|---|---|
| Primary assessment | `reports/R4_depSNORT_assessment.md` |
| Session transcript | `reports/R4_transcript.md` |
| Field notes | `reports/R4_field_notes.md` |
| Full-scope transcript | `reports/R4_full_session_transcript.md` (this file) |
| Scans | `scan-repo.json`, `scan-pinned.json`, `scan-pinned.sarif`, `scan-pinned.pdf` |
| Repro input | `pinned-requirements.txt`, `pinned-scan-dir/requirements.txt` |

Commits on `claude/new-session-3bsc72`:
- `982a5f6` — reports + scans + pinned-requirements.
- `74e2e37` — scan-pinned.pdf + pinned-scan-dir input.
- (this file added in a follow-up commit.)
Pushed to `origin/claude/new-session-3bsc72` (retry-with-backoff wrapper; first
attempt succeeded each time).

## Deviations / notes

- `pip-compile` installed mid-session (not preinstalled); anticipated by the prompt.
- OSV unreachable through proxy — recorded as a disclosure-behaviour observation,
  not worked around.
- Scratch files (`*.err`, throwaway `scan-zero.sarif`) were test byproducts and
  were removed rather than committed, to keep the tree clean.
- No PR was created (none requested).
- One field note (FN-01): "root(s)" terminology overload in coverage messaging.

*HoneyBadger Vanguard LLC internal research, project iHBV-TM-022. Internal
purple-team use.*
