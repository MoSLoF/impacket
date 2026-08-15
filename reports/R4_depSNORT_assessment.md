# TM-022 Round 4 — Independent depSNORT Depth Validation

**Project:** iHBV-TM-022 (HoneyBadger Vanguard LLC internal purple-team research)
**Session:** Round 4, Session 1 (standalone, blind/independent)
**DTG (UTC):** 2026-08-15T00:07Z
**Analyst model:** claude-opus-5

This assessment stands on its own facts. It does not reference, diff against,
or reconcile with any prior TM-022 run. Every claim below is grounded in output
produced during this session against the targets as they were checked out.

---

## Build state (recorded, not compared)

| Target | Value |
|---|---|
| depSNORT commit | `9b9f56778bc17f9e4520aa3baf2e886a78589fd1` |
| depSNORT tag | untagged |
| depSNORT `version` string | `dev` |
| depSNORT deps | zero third-party (no `go.sum`, no `require` block); `sbom` reports 0 components — dogfood claim holds |
| Toolchain | Go 1.24.7, `CGO_ENABLED=0`, clean build (exit 0) |
| impacket HEAD | `4c09897a8645818e873787f2c79ec1bce90c5777` ("Fix some SMB relay server syntax error (#2245)") |
| impacket version tag | none — this fork carries **0** tags; no `impacket_0_13_1`-style tag exists |
| impacket branch | `claude/new-session-3bsc72` |

The build pulled no external modules. `go.mod` documents the zero-dependency
constraint (Decision D-10) and there is no `go.sum`; `./depsnort sbom` returns an
empty `components` array. The tool genuinely audits clean against itself.

---

## PRIMARY FINDING — Dependency graph topology

This is the question the session exists to answer. It was answered by direct
inspection of `scan-pinned.json` (node list, edge list, per-node depth), not by
reading a flag.

```
GRAPH TOPOLOGY
node count: 32   (21 package nodes incl. root + 11 install-hook nodes)
edge count: 34   (23 depends-on + 11 declares-hook)
structure: GENUINE MULTI-LEVEL — the depends-on subgraph spans depths 0 -> 4,
           with shared sub-dependencies that have multiple distinct parents.
           This is NOT a flat single-level star.
example of real transitive edge:
   pkg:pypi/pyopenssl@26.4.0
     -> pkg:pypi/cryptography@50.0.0
       -> pkg:pypi/cffi@2.1.1
         -> pkg:pypi/pycparser@3.0        (root -> depth 4)
   (also: flask -> jinja2 -> markupsafe ; flask -> werkzeug -> markupsafe)
metadata field claiming to describe this: depsnort.flat_resolution
   (constant graph.AttrFlatResolution, value would be "pypi")
value observed: ABSENT — the field is not present on the root node or anywhere
   in the JSON (grep for "flat" across scan-pinned.json returns 0 matches).
does metadata agree with direct graph inspection: YES.
   The flat-resolution flag is set only when NO input line carries `# via`
   provenance. Here the pip-compile output carried provenance, the adapter built
   real edges from it, and the flag was correctly withheld. Flag and topology
   agree: the graph is genuinely transitive.
```

### Why this is unambiguously multi-level (evidence, not assertion)

1. **Depth exceeds 1.** A flat star has every dependency at depth 1. Here the
   maximum depth is **4** (`pycparser@3.0`), with populated intermediate depths
   2 and 3. Per-node `depth` values come straight from the JSON.

2. **depends-on edges (23) exceed package-count-minus-one (20).** A tree/star of
   21 package nodes has at most 20 edges. Observing 23 means at least three
   packages have more than one parent — impossible in a star:
   - `markupsafe@3.0.3` has **3** parents: `flask`, `jinja2`, `werkzeug`
   - `pyasn1@0.6.4` has **2** parents: `ldap3`, `pyasn1-modules`

3. **Only 7 of 20 dependencies are `direct`.** The remaining 13 are reached
   transitively through intermediate packages, e.g. `cffi` and `pycparser` are
   reachable only via `pyopenssl -> cryptography`.

The full depends-on edge list (23 edges) and the node/depth table are reproduced
in `R4_transcript.md`.

### Necessary caveat on input provenance

The multi-level structure is only as good as the input. depSNORT does **not**
run a resolver (Decision D-01) — it reconstructs edges from `# via` annotations
that `pip-compile` emits. Against impacket's **as-shipped** `requirements.txt`
(loose specifiers, no pins, no provenance) the same tool produced a **2-node /
1-edge** graph and disclosed 10 unresolved dependencies. So the topology is a
faithful reflection of what the input file expresses: flat in, flat out;
provenance in, transitive out. The tool does not fabricate structure, and it
does not collapse structure that is present. Both directions were observed
this session.

---

## Findings

### FINDING: DEP-01 — Post-dormancy release on a transitive crypto dependency
```
FINDING: DEP-01 — pyasn1 0.6.4 published after prolonged dormancy
TOOL/CHECK: depSNORT [VC-004]
SEVERITY: advisory
EXIT CODE: 0 (advisory does not gate)
DESCRIPTION: VC-004 fired on pyasn1@0.6.4: "0.6.4 published after 492d of
  dormancy" (gap 0.6.1 -> 0.6.2, 492d, 2024-09-10 -> 2026-01-16).
  confidence 0.4, recency_decay ~0.198, score ~0.0397.
PACKAGE(S): pkg:pypi/pyasn1@0.6.4
OPERATIONAL NOTE: pyasn1 is a transitive dependency reached via both ldap3 and
  pyasn1-modules — i.e. impacket's LDAP/Kerberos path. A long dormancy gap
  followed by a new release is a weak account-takeover signal, not evidence of
  compromise. It is correctly an advisory (does not fail a gate). Worth a human
  glance at the pyasn1 0.6.2+ publishing history before pinning forward; not a
  blocker. This was the ONLY check that fired in the scan.
```

### FINDING: DEP-02 — Install-surface extraction is capability-aware and does NOT over-alert
```
FINDING: DEP-02 — 11 install hooks extracted, all adjudicated clean (VC-002 precision holds)
TOOL/CHECK: depSNORT [VC-002a..f]
SEVERITY: informational
EXIT CODE: 0
DESCRIPTION: depSNORT fetched sdists from PyPI and extracted 11 install-hook /
  build-backend nodes across the pinned tree (setup.py module-level code,
  cmdclass.build_ext overrides, pyproject build-backends). Several carry
  capability facts: cap.env=true (reads os.environ), cap.exec=true (subprocess/
  compiler invocation), cap.filesystem=true. EVERY hook node resolved to
  risk=clean. No VC-002a-f finding was raised.
PACKAGE(S): cffi, cryptography, charset-normalizer, ldap3, markupsafe,
  pycryptodomex, pyopenssl, six (native-extension / legacy-setup.py packages)
OPERATIONAL NOTE: This is the precision behaviour the mission asked to verify.
  Broad os.environ access alone did NOT trigger VC-002c — that check is reserved
  for NAMED credentials/secret files. Generic subprocess + env + filesystem
  capability on a native-extension build (normal for cffi/cryptography/
  pycryptodomex) is recorded as fact but not escalated to a signal. The discipline
  ("only named secrets trigger") holds on this target. VC-002 did not manufacture
  a false positive from an ordinary C-extension build.
```

### Non-firing checks (recorded)
- **VC-001 (known-malicious block):** did not fire. But see coverage caveat —
  VC-001 depends on OSV, which was unreachable this session, so this is *not* an
  all-clear (see below). No `MAL-*` was asserted either way.
- **VC-005 (release burst), VC-006 (typosquat), VC-007 (dependency confusion):**
  did not fire. No `-internal-names/-internal-scopes` were supplied, so VC-007
  had nothing to match against (expected).
- **VC-008 (CVE):** could not run — OSV-dependent, OSV degraded (see below).

---

## Coverage completeness — does the tool disclose what it could not check?

**Yes, loudly, through every channel.** Tested directly, not assumed:

| Channel | Disclosure observed |
|---|---|
| stderr | `WARNING - coverage is incomplete: 15 unresolved dependenc(ies) ... degraded data source(s): osv. This report is NOT an all-clear.` |
| JSON `verdict.coverage` | `complete:false, degraded:true, unresolved_dependencies:15, incomplete_roots:15`, with per-node `unresolved_names` (`flit_core`, `maturin`, `hatchling`, `setuptools`) |
| JSON `data_sources[osv]` | `queried:20, gaps:20, from_network:0, advisories:0`, plus explicit `error: "...Forbidden"` |
| SARIF | `runs[0].invocations[0].toolExecutionNotifications` carries both the incompleteness warning and the OSV-degraded warning at `level:warning` |
| Exit code | `-fail-on-incomplete` returns **3** |

The 15 "unresolved" are the **build backends** (`flit_core`, `maturin`,
`hatchling`, `setuptools`) that each pinned package's sdist declares but which
are not themselves pinned in `pinned-requirements.txt`. depSNORT names them
rather than silently treating the tree as fully resolved. This is the correct,
conservative behaviour: it reports what it could not see.

---

## SARIF parity

- **Incomplete-coverage / OSV-degradation info IS present in SARIF**, not
  JSON-only. It surfaces as `invocations[].toolExecutionNotifications` (two
  `warning`-level notifications: coverage-incomplete and osv-degraded). A SARIF
  consumer that reads notifications sees the same "NOT an all-clear" signal the
  JSON carries.
- **Findings parity:** the VC-004 advisory appears as a SARIF `result`
  (`ruleId: VC-004`, `level: note`). The advisory→`note` severity mapping is
  reasonable.
- **Zero-finding serialization:** a genuinely finding-free run
  (`scan -format sarif -no-registry -no-osv`) serializes `runs[0].results` as an
  **empty array `[]`**, not `null`. This is spec-clean — SARIF requires `results`
  to be an array, and `[]` will not choke ingesters that reject `null`.

---

## OSV reachability

- **Attempted live, failed.** depSNORT's OSV client got HTTP `Forbidden` from
  `POST https://api.osv.dev/v1/querybatch`. A direct `curl` to the same endpoint
  from this environment returns `HTTP 000` (connection refused/blocked by the
  agent proxy — `api.osv.dev` is not on the egress allowlist).
- **Failure mode:** blocked at the egress proxy. This is an **environment
  constraint, not a depSNORT defect**.
- **Did the tool reflect it correctly?** Yes. It recorded `queried:20, gaps:20,
  from_network:0` and an explicit `error` string, set `coverage.degraded:true`,
  and refused to present the OSV-backed checks (VC-001, VC-008) as passed. It did
  **not** silently report zero malicious / zero CVE as if OSV had answered. This
  is the single most important coverage behaviour and it is correct.
- **Contrast:** PyPI itself (`pypi.org` / `files.pythonhosted.org`) *was*
  reachable — registry metadata (VC-004) and sdist fetch (install-surface) ran on
  live data. So the degradation is specific and correctly scoped to OSV, not a
  blanket offline state.

---

## Exit-code contract (recorded — these are findings, not incidentals)

| Run | Command | Exit |
|---|---|---|
| 1 | `scan -fail-on-incomplete .` (impacket as-shipped) | **3** (10 unpinned) |
| 2 | `scan -format json pinned-scan-dir/` | **0** |
| 3 | `scan -fail-on-incomplete pinned-scan-dir/` | **3** (15 unpinned build backends) |
| 3 | `scan -fail-on-eligible pinned-scan-dir/` | **0** (0 gate-eligible; 1 advisory) |

The contract is coherent: `3` = degraded resolution, `2` = gate-eligible (not
triggered here), `0` = clean/advisory-only. `-fail-on-eligible` correctly did
**not** fire on an advisory-only result — advisories are non-gating by design and
the exit code honoured that.

---

## Tool evaluation

- **Build / self-audit:** Exemplary. Zero third-party deps, verifiable via empty
  SBOM and absent `go.sum`. A supply-chain tool that is itself supply-chain-clean
  is credible.
- **Coverage-disclosure accuracy:** Strong. Incompleteness is surfaced on stderr,
  in JSON (`verdict.coverage` + `data_sources[].error`), in SARIF
  (`toolExecutionNotifications`), and via exit code 3. It never presents a
  degraded scan as an all-clear. This is the tool's best quality.
- **VC-002 precision:** Holds on this target. Broad env/exec/filesystem
  capability on ordinary native-extension builds is recorded as fact but not
  escalated; no false positive. Named-secret gating is respected.
- **Exit-code reliability:** Coherent and reproducible across runs; determinism
  is a stated design goal (sorted nodes/edges) and the codes matched the
  documented contract.
- **Dependency-edge fidelity:** Genuine. Multi-level transitive edges with
  correct shared-parent fan-in, reconstructed from `# via` provenance without
  running a resolver, and no fabricated structure when provenance is absent.
  Faithful in both directions.
- **Version identification:** Weakest point — reports `version: dev`, not a
  semantic version (untagged build). The report's provenance therefore depends on
  the commit hash, not the tool's self-reported version. Fine for a lab build;
  would matter for audit trails in production.

---

## Bottom line

depSNORT's dependency-graph resolution produces **genuine multi-level structure**
when the input carries provenance, and it correctly reports a flat/degraded graph
(with explicit disclosure) when the input does not. Against pip-compiled impacket
dependencies it built a real 4-deep transitive graph with correct shared-parent
fan-in. The `depsnort.flat_resolution` flag agreed with direct inspection (absent,
because the graph is not flat). No known-malicious release was asserted — but that
absence is honestly qualified as OSV-degraded, not sold as an all-clear. One
advisory (VC-004 dormancy on `pyasn1@0.6.4`) and zero gate-eligible or blocking
findings. VC-002 install-surface precision held. This is a well-built, honest tool
on the evidence of this session.

*This assessment is part of HoneyBadger Vanguard LLC internal research under
project iHBV-TM-022. Findings are for internal purple-team use.*
