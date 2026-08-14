---
title: "Impacket Security Assessment"
subtitle: "TM-022 Purple Validation Harness · Wave 1"
author: "HoneyBadger Vanguard LLC"
project: "iHBV-TM-022"
date: "2026-08-14"
classification: "Internal — Purple Team Research"
---

# Impacket Security Assessment

**Program:** TM-022 Purple Validation Harness — Wave 1
**Project code:** iHBV-TM-022
**Subject:** [`fortra/impacket`](https://github.com/fortra/impacket) (Kerberos subsystem + supply-chain surface)
**Assessor:** HoneyBadger Vanguard LLC
**Date:** 14 August 2026
**Distribution:** Internal — Purple Team Research

---

## Executive Summary

This assessment covers two attack surfaces of the `impacket` library as consumed
on Windows-domain engagements:

1. **Correctness of the Kerberos credential-cache (ccache) parser** — the code
   that decides which cached ticket is used for a given request. A merged fix
   (PR #2242, master head `4c09897`) addresses one known crash class; this
   engagement adversarially tested six spec-derived boundary conditions across
   the pre-fix baseline (`243d64a^`, 0.13.1-equivalent) and the patched master.
2. **The dependency supply-chain** — every third-party Python package that
   ships alongside `impacket`, statically resolved and analysed with the
   `depSNORT` tool.

### Headline findings

| ID | Class | v0.13.1 | Master | Priority |
|----|-------|---------|--------|:--------:|
| **EC-04** | UTF-8 principal handling | crash + silent mojibake | **unchanged** | **HIGH** |
| **EC-06** | Expired / bad-flag ticket selection | silent-wrong-result | **unchanged** | **HIGH** |
| **EC-R** | No-`/` search SPN with `anySPN=True` | crash | **crash (RESIDUAL)** | Medium |
| EC-03 | S4U2Self ST for a user principal | silent-skip | unchanged | Medium |
| EC-01 | 3-part SPN in `anySPN` loop | crash (poisons whole cache) | fixed | — |
| EC-05 | Port specifier in SPN 2nd component | 3-part crash | fixed | — |
| EC-02 | Cross-realm referral TGT | correct | correct | — |
| **DEP-01** | Unpinned `requirements.txt` | — | gate-eligible (exit 3) | Medium |
| DEP-02 | pyasn1 dormancy signal (VC-004) | — | advisory | Watch |
| DEP-03 | Install-hook capabilities | — | **clean** (0/10 hooks) | — |

**Two findings the vendor's fix does not touch (EC-04, EC-06) outrank EC-01 on
operational risk**, per the "silent-wrong-result outranks crash" heuristic
governing this engagement. **A residual crash of the same structural class as
EC-01 survives on master (EC-R)** — the fix hardened the cached-server side of
the SPN parser but left the search-server side exposed. The supply-chain scan
returned zero block-class findings against the current transitive tree; the
one gate-eligible finding is that `requirements.txt` is entirely unpinned,
which prevents any CI supply-chain scanner from acting on a stable graph.

---

## 1. Scope and Objectives

### In scope

- `impacket/krb5/ccache.py` — Kerberos credential-cache parser and the
  `CCache.getCredential` service-principal matcher.
- Cross-file structural-assumption sweep across `impacket/krb5/` for the
  patterns identified in the primary target file.
- `impacket`'s declared and transitive Python dependency graph via
  `setup.py` and `requirements.txt`.

### Out of scope

- Live directory / Kerberos infrastructure. All fixtures are constructed
  in-memory or from crafted lockfiles; no live AD, KDC, or on-wire traffic.
- The SMB, LDAP, and DCE/RPC subsystems, beyond passing observation of
  the ccache API's callers.
- Rubeus and bloodyAD (assigned to separate Wave 1 sessions).
- Detection-side artefacts (a separate workstream).

### Objectives

1. Confirm the vendor's PR #2242 fully resolves the seed edge case (EC-01)
   under all spec-legal permutations, not merely the one in the original bug
   report.
2. Characterise five additional spec-derived boundary conditions
   (EC-02–EC-06) that a flat single-domain test lab would not produce.
3. Identify any residual instances of the same structural assumption
   elsewhere in the code base.
4. Produce an independent supply-chain risk view of `impacket`'s
   dependencies.

---

## 2. Methodology

### 2.1 Kerberos ccache (EC-01 – EC-06)

- **Spec first, code second.** Each edge case was scoped from
  RFC 4120, MS-KILE, or MS-SFU before the implementation was consulted,
  to prevent the implementation from anchoring expectations of what
  "should" work.
- **Fixture-driven and self-contained.** ccache principals were constructed
  in-memory via `types.Principal(<spn>)` → `ccache.Principal.fromPrincipal`,
  using the same API path that `fromTGT` and `loadKirbiFile` exercise. No
  live AD, no raw byte crafting. Fixtures are regenerable against future
  versions.
- **Differential across two versions.** All fixtures were run against
  both the pre-fix baseline (`243d64a^`, whose `getCredential` is
  byte-identical to the 0.13.1 source cited in the seed report) and the
  patched master (`4c09897`), with strict module isolation via `PYTHONPATH`
  from a neutral working directory.
- **Silent-wrong-result outranks crash.** A crash is loud and fails
  fast; a mis-selected credential produces confusing wire-level failures
  or, worse, uses a ticket the operator did not intend. Silent-wrong-result
  findings are prioritised above IndexError crashes.

### 2.2 Supply chain (DEP-01 – DEP-05)

- Static, non-executing scan via `depSNORT` (build `dev`, commit
  `5b02377`, Go 1.24, `CGO_ENABLED=0`). `depSNORT` parses lockfiles and
  manifests only; it never invokes `pip` or fires an install hook.
- Two runs against `impacket`: one against the repository as-shipped
  (unpinned `requirements.txt`), one against a machine-generated pin set
  produced by installing the declared deps into a scratch environment and
  reading `importlib.metadata`.
- Multiple output formats emitted (JSON, SARIF, DOT, PDF) for downstream
  ingestion.

### 2.3 Version identifiers

| Component | Reference | Commit |
|-----------|-----------|--------|
| impacket baseline (0.13.1-equivalent) | `243d64a^` | `2dae5c7` |
| impacket master (patched) | `master` | `4c09897` |
| Vendor fix (PR #2242) | `243d64a` | — |
| `depSNORT` | `master` | `5b02377` |

The `impacket_0_13_1` tag is not present in the `MoSLoF/impacket` fork,
so the baseline was taken as the commit immediately preceding the fix;
its `getCredential` implementation is line-for-line identical to the
0.13.1 source quoted in the seed bug report and is therefore a faithful
proxy for the function under test.

---

## 3. Environment

- Container: Linux 6.18.5 sandbox, Python 3.11, Go 1.24.7.
- Outbound egress is mediated by an agent proxy; `api.osv.dev` is denied
  at the gateway (HTTP 403 CONNECT). This affected only the OSV advisory
  tier of the supply-chain scan and is disclosed in the DEP-04 finding.
  All temporal registry sources (PyPI, npm, RubyGems, Cargo, Composer,
  NuGet) were reachable and cached locally.

---

## 4. Findings — Kerberos ccache

### 4.1 Summary matrix

| EC | Condition | v0.13.1 | Master | Same assumption elsewhere | Priority |
|----|-----------|---------|--------|---------------------------|:--------:|
| EC-01 | 3-part SPN in `anySPN` loop | crash (poisons cache) | correct | search-side residual (EC-R) | — (fixed) |
| EC-02 | Cross-realm referral TGT | correct | correct | n/a | Low |
| EC-03 | S4U2Self ST, no service type | machine ok; **user silent-skip** | same | n/a | Medium |
| EC-04 | Non-ASCII (UTF-8) principals | crash + mojibake | **unchanged** | systemic `six.b()` latin-1 | **High** |
| EC-05 | Port specifier in 2nd SPN component | 3-part: crash | correct | (subsumed by EC-01 fix) | — (fixed) |
| EC-06 | Expired / bad-flag ticket | silent-wrong-result | **unchanged** | selection layer ignores time & flags | **High** |
| EC-R | No-`/` search SPN | crash | **crash (residual)** | same file, search-side | Medium |

### 4.2 EC-01 — 3-part SPN in `CCache.getCredential` `anySPN` fallback

- **Spec basis:** MS-KILE §2.2 / RFC 4120 §6.2. An SPN's `serviceName` is a
  sequence of `KerberosString` components; three-component service
  principals (`service/host/domain`) are spec-legal and are produced when
  Windows caches a service ticket dumped from LSASS memory
  (e.g. via Rubeus `dump`), with the domain suffix appended as a third
  component.
- **File:** `impacket/krb5/ccache.py :: CCache.getCredential` (`anySPN` loop).
- **Baseline behaviour:** the `if find(b'/') >= 0` branch performs
  `split(b'/')[1].split(b'@')[1]`. For `LDAP/host/domain@REALM`,
  `split(b'/')[1]` returns the *host* component, which contains no `@`, so
  `.split(b'@')[1]` raises `IndexError`.
- **Master behaviour:** the new `count(b'/') >= 2` branch (ccache.py:431–454)
  parses 3-part SPNs, strips an optional port from the 2nd component,
  handles ≥4-part shapes correctly, does short-name ⇄ FQDN matching only
  when at least one side is unqualified, and requires an exact realm match.
  Verified against all spec-legal permutations enumerated in the fixture
  harness.
- **Operational severity of baseline (poisoning):** the `anySPN` loop
  iterates every credential in the cache; a single 3-part ticket anywhere
  in `KRB5CCNAME` raises before the loop can reach the credential the
  caller asked for. Because `CCache.parseFile` unconditionally calls
  `getCredential('krbtgt/DOMAIN@DOMAIN', anySPN=True)`
  (ccache.py:667), a single dumped LDAP ticket in the operator's cache
  breaks plain TGT retrieval for the entire toolchain — `secretsdump`,
  `smbclient`, `getST`, and every other consumer — not merely LDAP
  operations.
- **Verdict:** the vendor fix is correct and complete for the cached-server
  side of `getCredential`. See EC-R for the residual search-side gap.

### 4.3 EC-02 — Cross-realm referral TGT `krbtgt/child.realm@parent.realm`

- **Spec basis:** RFC 4120 §3.3.3.
- **Result:** correct on both versions. A referral TGT is a well-formed
  two-part SPN carrying `@realm`, so it takes the standard branch and does
  not trip the EC-01 crash. It does not poison following credentials.
- **Priority:** Low. A latent, low-consequence note is that the two-part
  branch treats the referral's `CHILD.REALM` as the "host" component; a
  search for a service on a host literally named `child.realm` in
  `parent.realm` could in principle collide. This is not a realistic
  operational input.

### 4.4 EC-03 — S4U2Self ST with no service type (server principal has no `/`)

- **Spec basis:** MS-SFU §3.2.5.1.2. An S4U2Self ST's `sname` is the
  requesting principal; it may be a user (no service class) or a machine
  account (`host$`).
- **File:** `impacket/krb5/ccache.py :: getCredential`, no-slash branch.
- **Result:** the branch hardcodes `hostname$@REALM`
  (`searchSPN = "<short>$@<realm>"`).
  - Machine accounts match correctly (intended path).
  - **User principals silently miss:** an S4U2Self ST for
    `Administrator@REALM` (no `$`) is never matched by the `anySPN`
    fallback, because the appended `$` guarantees a miss.
- **Severity:** Medium. The failure is fail-closed (returns `None`, caller
  falls back to requesting a fresh ticket), so it does not corrupt state;
  however, an operator relying on a cached user-ST via `anySPN` will
  silently not get one. Present identically on both versions.

### 4.5 EC-04 — Non-ASCII (UTF-8) principal / realm handling (HIGH)

- **Spec basis:** RFC 4120 §5.2.1 (KerberosString = IA5String, ASCII)
  extended by MS-KILE and real-world Windows/MIT/Heimdal practice to UTF-8
  principal and realm names.
- **File:** `impacket/krb5/ccache.py :: Principal.prettyPrint`, `getCredential`.
  Root cause is systemic use of `six.b()` (latin-1 encoding) across the
  code base; commit `8ea54fe` ("Modernize byte string normalization",
  PR #2243) modernised `dcerpc`, `ntlm`, and examples but does not touch
  `ccache.py` or the principal-encoding path.
- **Two distinct failure modes:**
  1. **Silent mojibake (latin-1 range: `é ü ö ä ñ …`).** `six.b('café')`
     returns `b'caf\xe9'` (latin-1), not the UTF-8 `b'caf\xc3\xa9'` that
     real ccaches store. When a `Principal` is built from a string, its
     components are stored as `str` and re-encoded latin-1 on
     `prettyPrint`/`getData`. A ccache **written** by impacket with
     accented names is therefore byte-incompatible with MIT, Heimdal,
     and Windows, and cross-tool SPN comparison silently mismatches.
  2. **Hard crash (outside latin-1: Cyrillic, Greek, CJK, emoji, Hebrew).**
     `six.b('МОСКВА')` raises `UnicodeEncodeError`. This fires on the very
     first line of `getCredential` (`b(server.upper())`), so any lookup
     whose search SPN contains a non-latin-1 character crashes; the same
     is true for `parseFile` on a cache whose principal has such a name.
- **Read-only display of a genuine UTF-8 ccache is safe** — bytes loaded
  from disk pass through `prettyPrint` untouched. The break is on the
  construction, comparison, and re-encoding paths.
- **Operational impact:** engagements in organisations that use
  accented or localised `sAMAccountName` values or realm strings (common
  in EMEA, LATAM, and APAC) encounter silent wrong-results or hard stops
  with no obvious cause. Identical behaviour on both versions.

### 4.6 EC-05 — Port specifier in SPN second component

- **Spec basis:** MS-KILE SPN grammar:
  `serviceclass "/" hostname [":" port] ["/" servicename]`.
- **Result:**
  - Two-part with port (`HTTP/web.lab.local:8443`): both versions strip the
    port and match correctly.
  - Three-part with port (`LDAP/dc.lab.local:3268/lab.local@REALM`)
    against a two-part search: **baseline `IndexError`** — a second
    independent trigger of the EC-01 crash class. Master strips the
    port in the new 3-part branch and matches correctly.
- **Verdict:** fully resolved on master. All combinations verified
  (two-part, two-part+port, three-part, three-part+port, four-part).

### 4.7 EC-06 — Mixed / expired / unusual ticket flags (HIGH)

- **Spec basis:** RFC 4120 §5.3 (`endtime`, `renew-till`) and §2
  (`TicketFlags`: FORWARDABLE, RENEWABLE, and related bits). A consumer
  choosing a cached ticket is expected to honour the validity window and
  any required flags.
- **File:** `impacket/krb5/ccache.py :: getCredential` (selection layer).
- **Result:** `Credential` parses and stores `time.endtime`,
  `time.renew_till`, and `tktflags`, but these fields are consulted only
  for pretty-printing and re-serialisation. `getCredential` selects the
  **first structural SPN match**, unconditionally.
- **Verified:** a cache holding, for the same SPN, an expired
  non-forwardable ticket at index 0 and a valid forwardable ticket at
  index 1 returns the expired non-forwardable one. Order-dependent;
  identical on both versions.
- **Operational consequences:**
  - *Expired ticket:* no local pre-flight check; the dead ticket is handed
    downstream and fails at the KDC/target
    (`KRB_AP_ERR_TKT_EXPIRED`) — a confusing wire-level failure rather than
    a clean "ticket expired, re-authenticating" locally.
  - *Flags:* a delegation flow (S4U2Proxy) that requires FORWARDABLE will
    happily receive a non-forwardable cached TGT; the requirement is only
    ever (perhaps) enforced by the KDC, not by impacket's selection.
    "Forwarded but not forwardable" and non-renewable tickets are likewise
    never filtered.

### 4.8 EC-R — Residual: no-`/` search SPN with `anySPN=True` (survives on master)

- **Class:** same as EC-01 — an unconditional `split('/')[1]` index on the
  *search* side.
- **File:** `impacket/krb5/ccache.py :: getCredential`, lines 458–459 and 466
  (search side).
- **Result:** the EC-01 patch hardened the *cached-server* side against
  missing components but left the *search-server* side assuming the
  caller's SPN always contains a `/`
  (`server.upper().split('/')[1]`, ccache.py:458, 459, 466). If
  `getCredential` is called with a no-slash target (e.g. a bare
  `host@REALM` or `user@REALM`) **and** the cache contains any
  slash-bearing credential, the `anySPN` loop raises `IndexError` on
  master.
- **Reachability:** `CCache.parseFile` builds
  `principal = '<target>@<domain>'` from a caller-supplied `target`
  (ccache.py:660). Every in-tree caller currently passes a full SPN or
  `krbtgt/…` (both contain `/`), so the primary tools are not exposed on
  the current call sites. `getCredential` is public API, however, and is
  used by external tooling and by `examples/getST.py:184` with the default
  `anySPN=True`; any caller passing a no-slash target trips it.
- **Recommendation:** apply the same defensive guard
  (`len(parts) > 1` / `count('/')`) on the search side. This is a
  one-line fix of the same class as the vendor's cached-side patch.

### 4.9 Cross-file assumption sweep

`grep -rn "split(b'/')\[1\]|split('/')\[1\]|split('@')\[1\]"` across
`impacket/krb5/` returns matches only in
`ccache.py :: getCredential` (lines 457–466). The unconditional-index SPN
pattern is not duplicated in `kerberosv5.py`, `kpasswd.py`, `types.py`,
or elsewhere. `kpasswd.py:363` invokes
`getCredential(principal, anySPN=False)`, which never enters the fragile
loop.

The `six.b()` latin-1 assumption underlying EC-04, by contrast, is
**systemic** across the code base. Commit `8ea54fe` modernised several
modules but explicitly did not touch `ccache.py` or the principal-encoding
path.

---

## 5. Findings — Supply Chain

### 5.1 Summary matrix

| ID | Class | Gate | Impact |
|----|-------|------|--------|
| DEP-01 | Unpinned deps (D-01) | **gate-eligible (exit 3)** | Reproducibility gap; scanners cannot gate on a fixed graph |
| DEP-02 | VC-004 dormancy on `pyasn1@0.6.4` | Advisory | Monitor next `pyasn1` release; crypto-critical dep |
| DEP-03 | VC-002 install-hook family | Clean (0/10 capable) | No exfil/cradle install hooks in transitive tree |
| DEP-04 | OSV.dev 403-blocked by environment | Gate-eligible (env) | Sandbox limitation; not an impacket issue |
| DEP-05 | VC-007 dependency confusion | n/a | Not exercised (no internal scopes declared) |

### 5.2 DEP-01 — `requirements.txt` is entirely unpinned

Every one of the ten declared runtime dependencies uses either a floating
name (`setuptools`, `six`, `charset_normalizer`, `pyasn1_modules`,
`pycryptodomex`, `pyOpenSSL`) or a lower-bound-only specifier
(`pyasn1>=0.2.3`, `flask>=1.0`, `ldapdomaindump>=0.9.0`, and the exclusion
list on `ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6`). No upper bound is set
anywhere.

Consequences:

- Every fresh `pip install impacket` picks whatever the resolver currently
  prefers. There is no cross-machine or cross-CI reproducibility of the
  dep tree.
- A compromised newer minor release of any dep is picked up silently until
  it is yanked upstream.
- Automated supply-chain scanners (depSNORT, `pip-audit`, `safety`, etc.)
  cannot act on a stable `package@version` graph. depSNORT correctly
  refuses to speculatively resolve unpinned specifiers (design decision
  D-01) and returns exit 3 under `-fail-on-incomplete`.

**Recommendation:** add a `requirements.lock` produced by `pip-compile` or
adopt `uv` / `Pipfile.lock`. Keep `requirements.txt` as the human-authored
input; use the lockfile for CI and reproducible installs.

### 5.3 DEP-02 — `pyasn1@0.6.4` published after 492 days of dormancy (VC-004)

The only substantive finding across the pinned scan. `pyasn1` was silent
for 492 days and then released 0.6.4 — the account-takeover shape depSNORT
watches for. Per VC-004's design this remains advisory unless the awakening
release also declares an install hook, which `pyasn1`'s does not (verified
in the install-surface subgraph — no `install-hook` node for
`pyasn1@0.6.4`).

No immediate action required, but `pyasn1` is a load-bearing Kerberos and
ASN.1 crypto dependency for `impacket`: a compromise of that maintainer
account would poison every `impacket` install. **Treat `pyasn1`'s next
release as one to watch, not one to auto-upgrade.**

### 5.4 DEP-03 — Install-surface subgraph: clean

depSNORT statically extracted install-time hooks from every resolved
dependency (npm-style lifecycle hooks, Python `setup.py` /
`build-backend` / `.pth` files, and equivalents in other ecosystems).
All ten `install-hook` nodes carry `capabilities: none` — no network
reach, no named-credential access, no decode-and-execute indirection,
no download cradle.

| Package | Hook site(s) |
|---------|--------------|
| `charset-normalizer` 3.4.6 | `pyproject.toml` build-backend, `setup.py` module-level |
| `ldap3` 2.9.1 | `setup.py` module-level |
| `pycryptodomex` 3.23.0 | `setup.py` module-level, `cmdclass.build_ext` |
| `pyOpenSSL` 26.4.0 | `pyproject.toml` build-backend, `setup.py` module-level |
| `setuptools` 68.1.2 | `setup.py` module-level, `cmdclass.install` |
| `six` 1.16.0 | `setup.py` module-level |

Notably, `setuptools`'s `cmdclass.install` was not misclassified as
exfil-capable; depSNORT's precision-first design (VC-002 only flags
*named* credential access, not blanket environment reads) held up on the
legitimate native-build shape. `impacket`'s own `setup.py` also parsed
clean — the `git` sub-process it invokes for versioning is neither a
network reach nor a credential read.

### 5.5 DEP-04 — Coverage: OSV.dev advisory tier unreachable in this environment

The engagement runner's egress proxy denies `api.osv.dev` at the gateway
(HTTP 403 CONNECT, verified in `__agentproxy/status`'s
`recentRelayFailures`). depSNORT reported the degradation correctly and
returned exit 3 under `-fail-on-incomplete`. This is a sandbox
limitation, not an impacket property, and is documented for
reproducibility. On a network-connected host (or with a pre-fetched
`-osv-snapshot` file), the OSV advisory tier would run against the same
pin set.

### 5.6 DEP-05 — VC-007 dependency confusion (not exercised)

The dependency-confusion check requires the operator to declare internal
scopes/names via `-internal-scopes` / `-internal-names`. `impacket` ships
no internal package names, so VC-007 correctly no-op'd. Recorded here so
the matrix is complete.

---

## 6. Recommendations

Ranked by operational impact.

1. **EC-04 (High) — normalise principal handling to UTF-8.** Replace
   `six.b()` on the principal-encoding path with explicit
   `str.encode('utf-8')` on write and `bytes.decode('utf-8')` on
   compare. Add fixtures with accented and non-latin-1 principal names
   to `tests/misc/test_ccache.py`. This closes both the silent-mojibake
   and the hard-crash paths.
2. **EC-06 (High) — filter cached tickets on validity and required flags.**
   The selection layer (or its callers) should skip expired tickets and
   accept a `required_flags` argument, or at minimum expose `endtime` and
   `tktflags` on the return value so consumers can filter. First-match
   selection over an unfiltered list is the wrong default for a ticket
   cache.
3. **EC-R (Medium) — apply the same length guard on the search side of
   `getCredential`.** One-line defensive check (`if '/' in server:` /
   `len(parts) > 1`) at ccache.py:458 and 466. This closes the residual
   crash of the class that PR #2242 was opened to address.
4. **EC-03 (Medium) — allow the no-slash branch to match user
   principals**, or document that `anySPN` resolves only machine-account
   S4U2Self STs.
5. **DEP-01 (Medium) — add a machine-generated pin set** so CI can gate
   on a stable graph, supply-chain scanning has a concrete
   `package@version` to match against, and dormancy-then-release events
   (DEP-02) become actionable rather than advisory noise.

---

## 7. Reproducibility

All fixtures and scans are committed on branch
`claude/impacket-adversarial-wave-1-39koer`.

### Kerberos ccache differential

```bash
# baseline (0.13.1-equivalent)
git worktree add /tmp/prefix-tree 243d64a^

# from a NEUTRAL working directory (repo root shadows PYTHONPATH)
(cd /tmp && PYTHONPATH=/tmp/prefix-tree python3 tm022_wave1_harness/harness.py)
(cd /tmp && PYTHONPATH=/path/to/impacket python3 tm022_wave1_harness/harness.py)

# EC-04 layer analysis
(cd /tmp && PYTHONPATH=… python3 tm022_wave1_harness/ec04.py)
# EC-06 ordering test
(cd /tmp && PYTHONPATH=… python3 tm022_wave1_harness/ec06.py)
```

### Supply-chain scan

```bash
# depSNORT build (Go 1.24+, no network needed)
CGO_ENABLED=0 go build -o depsnort ./cmd/depsnort

# repo scan (unpinned)
./depsnort scan /path/to/impacket

# CI gate on unpinned specifiers
./depsnort scan -fail-on-incomplete /path/to/impacket        # exit 3

# pinned scan (using the committed pin set)
./depsnort scan tm022_wave1_harness/depsnort-pinned-requirements.txt
```

---

## Appendix A — Committed artefacts (branch `claude/impacket-adversarial-wave-1-39koer`)

| Path | Contents |
|------|----------|
| `TM-022_Wave1_impacket_findings.md` | Full Kerberos ccache findings (this report's §4) |
| `TM-022_Wave1_depSNORT_findings.md` | Full supply-chain findings (this report's §5) |
| `TM-022_Wave1_depSNORT_report.pdf` | depSNORT-generated PDF of the pinned scan |
| `tm022_wave1_harness/harness.py` | Differential harness — EC-01, EC-02, EC-03, EC-05, and pathological shapes |
| `tm022_wave1_harness/ec04.py` | UTF-8 principal layer analysis |
| `tm022_wave1_harness/ec06.py` | Expired-ticket / flag ordering test |
| `tm022_wave1_harness/depsnort-scan-repo.json` | depSNORT JSON — unpinned scan |
| `tm022_wave1_harness/depsnort-scan-pinned.json` | depSNORT JSON — pinned scan |
| `tm022_wave1_harness/depsnort-scan-pinned.sarif` | depSNORT SARIF — CI ingestion |
| `tm022_wave1_harness/depsnort-pinned-requirements.txt` | Reproducible 10-of-10 pin set |
| `reports/01_impacket_security_assessment.pdf` | This report, PDF form |
| `reports/02_depSNORT_tool_assessment.pdf` | Separate tool evaluation |
| `reports/03_session_transcript.pdf` | Complete assessment transcript |

## Appendix B — Version identifiers

| Component | Reference | Commit |
|-----------|-----------|--------|
| impacket baseline | `243d64a^` (0.13.1-equivalent) | `2dae5c7` |
| impacket master | `master` (patched) | `4c09897` |
| Vendor fix (PR #2242) | `243d64a` | — |
| `depSNORT` | `master` | `5b02377` |

---

*This report is internal HoneyBadger Vanguard LLC research under project
iHBV-TM-022 (TM-022 Purple Validation Harness). Distribute only within
the purple-team programme.*
