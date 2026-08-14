# TM-022 Wave 1 — impacket krb5 ccache adversarial assessment

**Subsystem:** `impacket/krb5/ccache.py` — `CCache.getCredential()` anySPN path
**Assessment type:** spec-legal edge-case differential (robustness / hardening)
**Date:** 2026-08-14

## Versions under test (real git state)

| Label | Commit | Meaning |
|-------|--------|---------|
| baseline | `2dae5c7f27cff3c95bf44d1ef93ff84e5b380b82` | parent of the fix — pre-fix behaviour |
| patched  | `243d64a67599e24a1c5dd7eb3ff8667d2d5bc2fc` | "Fix IndexError … 3-part SPNs" (PR #2242, 0x00Jeff / Fortra, 2026-08-10) |

`243d64a6` is an ancestor of `master` HEAD (`4c09897a`), so `master` carries
the fix. This fork has **no release tags**, so versions are referenced by commit
hash only — "master" is not used as a version reference. Both trees were checked
out into isolated worktrees and imported in separate subprocesses so the two
module trees never collide in one interpreter.

> **Note on sourcing.** This was run as a standalone, real-git-state hardening
> assessment. There is no Session-1 handoff file in this repository, and none
> was fabricated; the baseline/patched split is derived entirely from the fixing
> commit and its parent. Findings here are intended to be upstream-reportable.

## How to reproduce

```bash
git worktree add /tmp/impacket-baseline 2dae5c7f
git worktree add /tmp/impacket-patched  243d64a6
pip install pyasn1 six pycryptodomex --break-system-packages

# Differential across both versions:
python3 tm022_wave1_harness/harness.py \
    --baseline /tmp/impacket-baseline --patched /tmp/impacket-patched

# Single-version probes:
PYTHONPATH=/tmp/impacket-patched python3 tm022_wave1_harness/ec04.py
PYTHONPATH=/tmp/impacket-patched python3 tm022_wave1_harness/ec06.py
```

All fixtures are constructed in memory (`ccache.CCache()` +
`Principal.fromPrincipal`) — no live AD, no disk ccache, no secrets.

## Differential summary

| Case | Shape | baseline | patched | Δ |
|------|-------|----------|---------|---|
| EC-01a | 3-part SPN, direct lookup | **crash** (IndexError) | correct | **FIXED** |
| EC-01b | 3-part SPN, poisons unrelated lookup | **crash** (IndexError) | correct (None) | **FIXED** |
| EC-02 | cross-realm referral TGT | correct | correct | same |
| EC-03a | S4U2Self ST, machine account | correct | correct | same |
| EC-03b | S4U2Self ST, **user** account | **silent-wrong** | **silent-wrong** | same |
| EC-05a | 2-part SPN with port | correct | correct | same |
| EC-05b | 3-part SPN with port | **crash** (IndexError) | correct | **FIXED** |
| EC-R | no-slash **search** term | **crash** (IndexError) | **crash** (IndexError) | same |

Regressions introduced by the patch: **0**. The patch is a net positive — it
resolves EC-01/EC-05b with no observed regression on any other case. Two
pre-existing issues (EC-03b, EC-R) are **not** addressed by it and are the main
carry-forward findings below.

---

## EC-01 — 3-part SPN in the anySPN fallback  *(calibration — PASS)*

```
EDGE CASE: EC-01 — 3-part SPN (service/host/domain@REALM) in getCredential anySPN
SPEC BASIS: RFC 4120 §6.2 (principal names); MS-KILE §2.2 SPN grammar.
            Windows caches memory-dumped service tickets (e.g. Rubeus `dump`)
            with the domain appended as a 3rd component in multi-domain forests.
VERSIONS TESTED:
  baseline: 2dae5c7f (pre-fix)
  patched:  243d64a6 (PR #2242)
FILES AFFECTED: impacket/krb5/ccache.py — CCache.getCredential(), anySPN loop
OUTCOME baseline:  crash (IndexError: list index out of range)
OUTCOME patched:   correct
SAME ASSUMPTION ELSEWHERE: yes — search side (see EC-R); nowhere else in krb5/
FIXTURE: tm022_wave1_harness/harness.py  cases EC-01a / EC-01b
OPERATIONAL NOTE: one 3-part ticket ANYWHERE in the cache is enough. Callers
  issue getCredential('krbtgt/DOMAIN@DOMAIN', anySPN=True) unconditionally; the
  anySPN loop iterates every credential, so the crash fires when the loop reaches
  the 3-part entry — poisoning lookups for completely unrelated SPNs. On baseline
  a single dumped LDAP ticket breaks the whole cache; patched degrades to a clean
  miss (None) when there is genuinely no match.
```

**Spec vs implementation.** RFC 4120 places no cardinality limit on principal
name components; MS-KILE routinely produces 3-component SPNs. Baseline assumed
exactly two: `prettyPrint().split(b'/')[1].split(b'@')[1]` reads the realm off
the *second* component, but in a 3-part SPN the `@REALM` lives on the *third*,
so `[1]` has no `@` → `IndexError`.

**Calibration verdict.** Baseline reproduces the known crash; patched does not.
The harness catches a known bug, so it is trusted for the remaining cases.

**Patch audit (permutations).** The new `count(b'/') >= 2` branch was checked
against every MS-KILE permutation called out in the brief:
- Port in 2nd component (`LDAP/dc:3268/domain@REALM`) — handled: `.split(b':',1)[0]` strips the port (see EC-05b, passes).
- 4-part SPN — `cachedParts[-1]` / `serverParts[-1]` take the realm from the last component, so ≥3 parts are tolerated (realm still parsed correctly); host match uses `[1]`.
- Empty 3rd component (`LDAP/host/@REALM`) — realm is read from `cachedParts[-1].split(b'@')[-1]`; the empty middle does not break parsing.

---

## EC-02 — Cross-realm referral TGT

```
EDGE CASE: EC-02 — krbtgt/CHILD.REALM@PARENT.REALM (2-part, 2nd comp is a realm)
SPEC BASIS: RFC 4120 §3.3.3 (cross-realm referral).
VERSIONS TESTED: baseline 2dae5c7f / patched 243d64a6
FILES AFFECTED: impacket/krb5/ccache.py — anySPN 2-part branch
OUTCOME baseline:  correct
OUTCOME patched:   correct
SAME ASSUMPTION ELSEWHERE: n/a
FIXTURE: tm022_wave1_harness/harness.py case EC-02
OPERATIONAL NOTE: a referral TGT is a well-formed 2-part SPN; the fact that the
  2nd component is a realm rather than a hostname is irrelevant to the parser,
  which only splits on '/' , '@', ':'. No gap here on either version.
```

---

## EC-03 — S4U2Self ST with no service type  *(silent-wrong-result — carry-forward)*

```
EDGE CASE: EC-03 — no-slash principal in the S4U2Self ('else') branch
SPEC BASIS: MS-SFU §3.2.5.1.2 (S4U2Self); RFC 4120 §6.2.
VERSIONS TESTED: baseline 2dae5c7f / patched 243d64a6
FILES AFFECTED: impacket/krb5/ccache.py:465-466 (no-slash 'else' branch)
OUTCOME baseline:  correct for machine accounts / SILENT-WRONG for user accounts
OUTCOME patched:   correct for machine accounts / SILENT-WRONG for user accounts
SAME ASSUMPTION ELSEWHERE: no (this is the only '$'-appending branch)
FIXTURE: tm022_wave1_harness/harness.py cases EC-03a (machine) / EC-03b (user)
OPERATIONAL NOTE: the no-slash branch hard-codes the machine-account shape —
  it strips everything after the first '.' and appends '$':
  searchSPN = f"{host.split('.')[0]}$@{realm}". A machine account (US-DC$@REALM)
  matches. A user-principal S4U2Self ST (john.doe@REALM, no '$') can NEVER match:
  the constructed search key is 'JOHN$@REALM' and never equals the cached
  'JOHN.DOE@REALM'. getCredential returns None with no error. This is a
  silent-wrong-result — it outranks a crash because nothing signals the miss;
  the caller silently proceeds as if no cached ticket exists. Unchanged by the
  EC-01 fix (the fix does not touch the 'else' branch).
```

**Priority.** Higher than the crashes. A crash is loud and fails closed; this
fails *silent* — a valid cached credential is treated as absent.

---

## EC-04 — Non-ASCII (UTF-8) principal / realm

```
EDGE CASE: EC-04 — non-ASCII code points in the principal / realm
SPEC BASIS: RFC 4120 §5.2.1 (KerberosString) extended by MS-KILE (UTF-8 in
            practice); real forests DO issue tickets with non-ASCII names.
VERSIONS TESTED: baseline 2dae5c7f / patched 243d64a6
FILES AFFECTED: impacket/krb5/ccache.py:164 (Principal.prettyPrint -> b(...))
OUTCOME baseline:  latin-1 correct / Cyrillic crash (UnicodeEncodeError)
OUTCOME patched:   latin-1 correct / Cyrillic crash (UnicodeEncodeError)
SAME ASSUMPTION ELSEWHERE: any code path that calls Principal.prettyPrint()
FIXTURE: tm022_wave1_harness/ec04.py
OPERATIONAL NOTE: the layer probe pinpoints the failure earlier than a naive
  read predicts. It is NOT getCredential's own six.b(server.upper()) that fires
  first — it is Principal.prettyPrint(), which does b(component['data']) at
  ccache.py:164. six.b(s) on py3 == s.encode('latin-1'), so:
    - 'cifs/café.lab.local@LAB.LOCAL' (within latin-1) round-trips cleanly -> OK
    - 'cifs/СЕРВЕР@ДОМЕН.LOCAL' (Cyrillic, outside latin-1) -> UnicodeEncodeError
  getCredential calls prettyPrint() on the cached server as the first step of
  its loop, so the anySPN fallback is never reached. Identical on both versions —
  the EC-01 fix does not touch this path.
```

**Layer verdict.** Failure origin = `six.b` inside `Principal.prettyPrint`
(`ccache.py:164`), not `getCredential`, not `types.Principal`, not
`fromPrincipal`. A non-ASCII realm anywhere in the cache is enough to break
`prettyPrint`-driven iteration.

---

## EC-05 — Port specifier in SPN

```
EDGE CASE: EC-05 — serviceclass/hostname[:port][/servicename]@REALM
SPEC BASIS: MS-KILE SPN grammar.
VERSIONS TESTED: baseline 2dae5c7f / patched 243d64a6
FILES AFFECTED: impacket/krb5/ccache.py — anySPN 2-part and 3-part branches
OUTCOME baseline:  2-part+port correct / 3-part+port CRASH (IndexError)
OUTCOME patched:   2-part+port correct / 3-part+port correct
SAME ASSUMPTION ELSEWHERE: covered by EC-01 fix for the cached side
FIXTURE: tm022_wave1_harness/harness.py cases EC-05a / EC-05b
OPERATIONAL NOTE: the 2-part branch already stripped the port via .split(':')[0]
  on both versions. The 3-part+port combination is the strictest test of the
  patch's new branch: baseline crashes on the 3-part shape before the port is
  even considered; patched strips the port (.split(b':',1)[0]) AND parses the
  3rd-component realm, returning the right credential. The patch handles the
  full port × component-count matrix, not just the subset its comment implies.
```

---

## EC-06 — Selection under mixed expiry / ticket flags  *(behavioural — flagged for contract review)*

```
EDGE CASE: EC-06 — two credentials, same SPN, differing endtime + tktflags
SPEC BASIS: RFC 4120 §5.3 (endtime, renew-till); §2 (TicketFlags/forwardable).
VERSIONS TESTED: baseline 2dae5c7f / patched 243d64a6
FILES AFFECTED: impacket/krb5/ccache.py — getCredential exact-match loop
OUTCOME baseline:  first-match (index 0) returned — expired, non-forwardable
OUTCOME patched:   first-match (index 0) returned — expired, non-forwardable
SAME ASSUMPTION ELSEWHERE: selection is first-match throughout getCredential
FIXTURE: tm022_wave1_harness/ec06.py
OPERATIONAL NOTE: with index 0 = expired+non-forwardable and index 1 =
  valid+forwardable for the SAME SPN, getCredential returns index 0. It consults
  neither endtime nor the ticket flags — pure first-match on server SPN.
```

**Classification.** Recorded as **behavioural**, not a security severity. Whether
`getCredential()` should own expiry/flag filtering or whether that is the
caller's responsibility is a **contract question** and must be settled before any
patch recommendation. Flagged for contract review; deterministic fixed
timestamps (no wall-clock reads) make the fixture regenerable.

---

## EC-R — No-slash / 3-part **search** term  *(residual of the EC-01 class — promote)*

```
EDGE CASE: EC-R — the SEARCH-side mirror of the EC-01 assumption
SPEC BASIS: same as EC-01 (RFC 4120 §6.2 / MS-KILE §2.2).
VERSIONS TESTED: baseline 2dae5c7f / patched 243d64a6
FILES AFFECTED: impacket/krb5/ccache.py:458-459 (2-part branch, search side)
                impacket/krb5/ccache.py:466   (no-slash branch, search side)
OUTCOME baseline:  crash (IndexError)
OUTCOME patched:   crash (IndexError)   <-- NOT fixed
SAME ASSUMPTION ELSEWHERE: yes — this IS the same bug class, search side
FIXTURE: tm022_wave1_harness/harness.py case EC-R (+ /tmp probe in report notes)
OPERATIONAL NOTE: the vendor fix hardened only the CACHED-server side (the new
  count(b'/')>=2 branch inspects c['server']). The SEARCH-server side still does
  server.upper().split('/')[1].split('@')[1] with no guard that `server`
  contains a '/' or that its 2nd component carries the '@'. Two spec-legal
  search terms still IndexError on the PATCHED version:
    - 3-part search term  (LDAP/dc.lab.local/lab.local@LAB.LOCAL) vs a 2-part
      cached entry  -> split('/')[1]='dc.lab.local', .split('@')[1] -> IndexError
    - no-slash search term (US-DC$@US.TECHCORP.LOCAL)               vs any
      slash-bearing cached entry -> split('/')[1] -> IndexError
```

**Promotion rationale.** Per the assessment plan, a residual of the same class
found on the patched version is promoted to a first-class finding. The fix
closed the cached-server door and left the search-server door open. It is the
same one-line-class defect: index without a guard.

**Suggested hardening direction (upstream).** Parse the search SPN with the same
count-based dispatch the fix introduced for the cached side, and guard the index
before use — e.g. compute `searchParts = server.upper().split('/')` once and, in
the 2-part branch, `if len(searchParts) < 2: continue` (skip incomparable
entries rather than crash); handle the 3-part search shape symmetrically with the
cached-side logic (host = `searchParts[1]` minus port, realm = last component's
`@`-suffix). This keeps the search side and cached side structurally identical so
the two cannot drift apart again.

---

## krb5-subsystem sweep — same structural assumption elsewhere

```
grep -rn "split(b'/')\[1\]|split('/')\[1\]|split(b'@')\[1\]|split('@')\[1\]" impacket/krb5/
```

The only hits in the entire `impacket/krb5/` tree are inside
`ccache.py:getCredential()` (lines 457–466 on the patched tree). There is no
second file carrying the same unguarded split-index pattern. The assumption is
localised to this one function — but it lives on **both** sides of it (cached and
search), and the fix only reached one side (EC-R).

## Bottom line

- The EC-01 fix (`243d64a6`) is correct and regression-free across EC-01–EC-06; **adopt it.**
- **EC-R** is the same defect class left unpatched on the search side — a one-line-class guard closes it. Upstream-reportable.
- **EC-03b** is a silent-wrong-result (user-principal S4U2Self ST never matches) present on both versions; higher priority than a crash because it fails silent.
- **EC-06** (first-match, no expiry/flag filtering) and **EC-04** (non-ASCII realms crash in `prettyPrint` via `six.b`, see `ec04.py`) are pre-existing behaviours untouched by the fix; EC-06 needs a contract decision before any patch.
