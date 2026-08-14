# TM-022 Purple Validation Harness — Wave 1 / impacket Attack Pass

**Project:** iHBV-TM-022 (internal purple-team research)
**Subsystem under test:** `impacket/krb5` — Kerberos credential-cache parsing & SPN matching
**Date:** 2026-08-14
**Operator model:** claude-opus-4-8

## Versions under differential test

| Label | Ref | `getCredential` state |
|-------|-----|-----------------------|
| **baseline (0.13.1-equiv)** | `2dae5c7` (`243d64a^`) | pre-fix; `getCredential` byte-identical to the code quoted in the 0.13.1 bug report |
| **master (patched)** | `4c09897a8645818e873787f2c79ec1bce90c5777` (fix `243d64a`, PR #2242) | post-fix |

> The `impacket_0_13_1` tag is not present in the `MoSLoF/impacket` fork. The baseline
> tree is the commit immediately preceding the fix; its `getCredential` is line-for-line
> identical to the 0.13.1 source cited in the seed case, so it is a faithful 0.13.1 proxy
> for this function.

## Method

All fixtures are built **in-memory** — no live AD, no raw byte crafting required. A ccache
`Principal` is populated from `types.Principal(<spn-string>)`, exactly as impacket's own
`fromTGT`/`fromKirbi`/programmatic paths do. Each tree is loaded in isolation via
`PYTHONPATH` from a **neutral CWD** (running from the repo root puts `sys.path[0]` = repo
root and shadows `PYTHONPATH`; this was verified and controlled for). Harness scripts:
`scratchpad/harness.py`, `ec04.py`, `ec06.py`, `regr.py`.

Reproduce:
```bash
git worktree add /tmp/prefix-tree 243d64a^
# baseline
(cd /tmp && PYTHONPATH=/tmp/prefix-tree python3 harness.py)
# master
(cd /tmp && PYTHONPATH=/path/to/impacket python3 harness.py)
```

---

## Executive summary

| EC | Condition | v0.13.1 | master | Same assumption elsewhere | Priority |
|----|-----------|---------|--------|---------------------------|----------|
| EC-01 | 3-part SPN in anySPN loop | **crash (poisons whole cache)** | correct | search-side residual (see EC-R) | — (fixed) |
| EC-02 | cross-realm referral TGT `krbtgt/child@parent` | correct | correct | n/a | low |
| EC-03 | S4U2Self ST, no service type | correct (machine); **silent-skip (user)** | same | n/a | medium |
| EC-04 | non-ASCII (UTF-8) principal/realm | **crash + silent mojibake** | **crash + silent mojibake** (unchanged) | systemic `six.b()` latin-1 | **HIGH** |
| EC-05 | port in SPN 2nd component | 2-part correct; **3-part crash** | correct | — (fixed with EC-01) | — (fixed) |
| EC-06 | expired / bad-flag ticket | **silent-wrong-result** | **silent-wrong-result** (unchanged) | selection layer ignores time+flags | **HIGH** |
| EC-R | no-`/` search SPN + anySPN | **crash** | **crash (RESIDUAL)** | same file, search side | medium |

Two findings the EC-01 patch does **not** touch (EC-04, EC-06) are rated above EC-01 itself
on operational risk, per the "silent > crash" guardrail. One **residual crash of the same
structural class as EC-01 survives on master** (EC-R).

---

## EDGE CASE: EC-01 — 3-part SPN in CCache.getCredential anySPN fallback
```
SPEC BASIS: MS-KILE §2.2 / RFC 4120 §6.2 — an SPN's serviceName is a sequence of
            KerberosString components; 3-component service principals
            (service/host/domain) are spec-legal and are produced when Windows caches
            a service ticket dumped from LSASS (e.g. Rubeus `dump`), appending the
            domain suffix as a 3rd component.
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: CCache.getCredential (anySPN loop)
OUTCOME v0.13.1: crash — IndexError: list index out of range
OUTCOME master:  correct — matches on host+realm, strips optional port
SAME ASSUMPTION ELSEWHERE: yes (search-side) — see EC-R
FIXTURE: harness.py EC01-a / EC01-b / EC01-c
NOTES:
```
- Root cause (baseline): the `if find(b'/') >= 0` branch does
  `split(b'/')[1].split(b'@')[1]`. For `LDAP/host/domain@REALM`, `split(b'/')[1]` = the
  **host** component, which contains no `@`, so `.split(b'@')[1]` → IndexError.
- **Poisoning is confirmed and is the real operational severity** (EC01-b): the anySPN loop
  iterates *every* credential. One 3-part ticket **anywhere** in the cache raises before the
  loop can reach the credential you actually asked for. Because `CCache.parseFile()` calls
  `getCredential('krbtgt/DOMAIN@DOMAIN', anySPN=True)` on **every** invocation (ccache.py:667),
  a single dumped LDAP ticket in `KRB5CCNAME` breaks *plain TGT retrieval* for the entire
  toolchain — secretsdump, smbclient, getST, etc. — not just LDAP operations.
- Patch audit (master, ccache.py:431–454): new `count(b'/') >= 2` branch. It correctly:
  - handles the **port in the 2nd component** (`split(b':',1)[0]`) — verified EC-05c;
  - handles **≥4-part** SPNs (`cachedParts[-1]` for realm) — verified EX-a;
  - does **short-name ⇄ FQDN** matching only when one side is unqualified, and requires the
    realm to match, so it does **not** false-match a same-shortname host in a different child
    domain — verified by shipped regression test `wrong-child: NONE`.
  - The "3rd component itself contains `@`" permutation the brief asked about is **not
    reachable from a parsed ccache** (realm is stored in a separate field, never inside a
    component); it can only be forged via an escaped `\@` in a constructed `types.Principal`,
    where `cachedHost` would truncate at the `@` — a benign non-issue since `@` is not a legal
    host character.
- Calibration verdict: **PASS.** Crash reproduced on baseline (direct + poisoning), absent on
  master; shipped regression test passes on master, IndexError on baseline.

## EDGE CASE: EC-02 — Cross-realm referral TGT `krbtgt/child.realm@parent.realm`
```
SPEC BASIS: RFC 4120 §3.3.3 — cross-realm TGTs carry sname krbtgt/<next-realm>.
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: CCache.getCredential
OUTCOME v0.13.1: correct
OUTCOME master:  correct
SAME ASSUMPTION ELSEWHERE: n/a
FIXTURE: harness.py EC02-a/b/c
NOTES:
```
- `krbtgt/CHILD.REALM@PARENT.REALM` is a well-formed **2-part** SPN (one `/`, and it *does*
  carry an `@realm`), so it takes the standard `elif find(b'/') >= 0` branch and never hits
  the missing-`@` crash. No crash, and it does **not** poison following credentials (EC02-c).
- Latent, very-low-risk note: the 2-part branch treats the referral's `CHILD.REALM` as the
  "host" component. A search for a *service on a host literally named* `child.realm` in
  `parent.realm` could in principle collide, but this is not a realistic operational input.
  Not a gap in either version.

## EDGE CASE: EC-03 — S4U2Self ST with no service type (server principal has no `/`)
```
SPEC BASIS: MS-SFU §3.2.5.1.2 — an S4U2Self ST's sname is the requesting principal, which
            may be a user (no service class) or a machine account (host$).
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: getCredential (else / no-slash branch)
OUTCOME v0.13.1: correct for machine accounts; SILENT-SKIP for user principals
OUTCOME master:  same (branch untouched by the patch)
SAME ASSUMPTION ELSEWHERE: n/a
FIXTURE: harness.py EC03-a/b/c
NOTES:
```
- The no-slash branch hardcodes `hostname$@REALM` (`searchSPN = "<short>$@<realm>"`). It
  correctly matches a **machine-account** ST to a `cifs/<host>` search (EC03-b MATCH) — the
  intended path.
- **Silent-skip finding:** a *user* S4U2Self ST (`Administrator@REALM`, no `$`) is never
  matched by the anySPN fallback — the appended `$` guarantees a miss (EC03-a NONE). This is
  fail-closed (returns `None`, caller falls back to requesting fresh), so it is lower severity
  than a wrong match, but an operator relying on a cached user-ST via anySPN will silently not
  get it. Present identically in both versions.

## EDGE CASE: EC-04 — Non-ASCII (UTF-8) username / realm in ccache principal fields
```
SPEC BASIS: RFC 4120 §5.2.1 (KerberosString = IA5String, ASCII) extended by MS-KILE and
            real-world Windows/MIT/Heimdal practice to UTF-8 principal names.
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: Principal.prettyPrint, getCredential;
                  root cause is six.b() latin-1 normalization used tree-wide.
OUTCOME v0.13.1: crash (non-latin1) + silent-mojibake (latin1 range)
OUTCOME master:  identical — the EC-01 patch and commit 8ea54fe ("Modernize byte string
                 normalization", #2243) do NOT touch this path.
SAME ASSUMPTION ELSEWHERE: yes — systemic. six.b()/`b(...)` latin-1 assumption pervades
                 the codebase; 8ea54fe modernized dcerpc/ntlm/examples but not ccache or
                 the principal-encoding path.
FIXTURE: ec04.py
NOTES (HIGH — two distinct failure modes):
```
1. **Silent mojibake (latin-1 range: é ü ö ä ñ …).** `six.b('café')` = `b'caf\xe9'`
   (latin-1), **not** UTF-8 `b'caf\xc3\xa9'`. When a `Principal` is built from a string
   (`types.Principal` → `fromPrincipal`), its components are stored as `str` and
   `prettyPrint`/`getData` encode them latin-1. A ccache **written** by impacket with
   accented names is therefore **byte-incompatible** with MIT/Heimdal/Windows (which store
   UTF-8), and cross-tool SPN comparison silently mismatches. Verified: construct-from-string
   yields `b'caf\xe9'`; a genuinely UTF-8-loaded principal yields `b'caf\xc3\xa9'` — the two
   never compare equal.
2. **Hard crash (outside latin-1: Cyrillic, Greek, CJK, emoji, Hebrew…).** `six.b('МОСКВА')`
   → `UnicodeEncodeError: 'latin-1' codec can't encode…`. This fires in `Principal.prettyPrint`
   and in `getCredential`'s very first line `b(server.upper())`, so **any** lookup whose search
   SPN contains a non-latin-1 character crashes — and so does `parseFile` on a cache whose
   principal has such a name.
- The **loaded-from-disk** path (components arrive as raw UTF-8 *bytes*) survives `prettyPrint`
  (bytes pass through untouched), so read-only display of a real UTF-8 ccache is safe; the
  break is on the **construction/compare/encode** side.
- Operationally: engagements in orgs using accented/localized sAMAccountNames or realm names
  (common in EU/LATAM/APAC) hit silent wrong-results or hard stops with no obvious cause.

## EDGE CASE: EC-05 — Port specifier in SPN second component
```
SPEC BASIS: MS-KILE SPN grammar — serviceclass "/" hostname [":" port] ["/" servicename].
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: getCredential
OUTCOME v0.13.1: 2-part-with-port correct; 3-part-with-port CRASH
OUTCOME master:  all combinations correct
SAME ASSUMPTION ELSEWHERE: covered by the EC-01 fix
FIXTURE: harness.py EC05-a/b/c/d
NOTES:
```
- 2-part + port (`HTTP/web.lab.local:8443`): both versions strip the port and match (EC05-a/b).
- 3-part + port (`LDAP/dc.lab.local:3268/lab.local@REALM` vs 2-part search): **baseline
  IndexError** (EC05-c) — this is a *second, independent trigger of the EC-01 crash class*
  (any 3-part SPN crashes on baseline, port or not). Master strips the port in the new 3-part
  branch and matches correctly. The brief's concern that the port-stripping "only handles the
  subset the comment implies" is **not** borne out on master — verified across
  {2-part, 2-part+port, 3-part, 3-part+port, 4-part}.

## EDGE CASE: EC-06 — Mixed / expired / unusual ticket flags
```
SPEC BASIS: RFC 4120 §5.3 (endtime, renew-till) and §2 (TicketFlags: FORWARDABLE,
            FORWARDED, RENEWABLE, …). A consumer choosing a cached ticket is expected to
            honour validity window and required flags.
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: getCredential / parseFile (selection layer)
OUTCOME v0.13.1: silent-wrong-result
OUTCOME master:  silent-wrong-result (unchanged)
SAME ASSUMPTION ELSEWHERE: yes — the selection layer categorically ignores time & flags.
FIXTURE: ec06.py
NOTES (HIGH — silent):
```
- `Credential` parses and stores `time.endtime`, `time.renew_till`, and `tktflags`, but these
  are used **only** for pretty-printing and re-serialization. `getCredential` selects the
  **first structural SPN match**, full stop.
- Verified (ec06.py): a cache holding, for the same SPN, an **expired non-forwardable** ticket
  at index 0 and a **valid forwardable** ticket at index 1 → `getCredential` returns the
  **expired non-forwardable** one. Order-dependent, both versions identical.
- Consequences for an operator mid-engagement:
  - **Expired**: no local pre-flight check; the dead ticket is handed downstream and fails at
    the KDC/target (`KRB_AP_ERR_TKT_EXPIRED`) — a confusing wire-level failure rather than a
    clean "ticket expired, re-authenticating" locally.
  - **Flags**: a delegation flow (S4U2Proxy) that requires FORWARDABLE will happily receive a
    non-forwardable cached TGT; the requirement is only ever (maybe) enforced by the KDC, not
    by impacket's selection. "forwarded-but-not-forwardable" and non-renewable tickets are
    likewise never filtered.

## EDGE CASE: EC-R — RESIDUAL: no-`/` search SPN with anySPN=True (survives on master)
```
SPEC BASIS: same class as EC-01 — an unconditional split('/')[1] index on the SEARCH side.
VERSION TESTED: 0.13.1 (2dae5c7) | master (4c09897)
FILE(S) AFFECTED: impacket/krb5/ccache.py :: getCredential lines 458–459 and 466 (search side)
OUTCOME v0.13.1: crash — IndexError
OUTCOME master:  crash — IndexError (NOT fixed by PR #2242)
SAME ASSUMPTION ELSEWHERE: same file, search-side of both the 2-part and no-slash branches.
FIXTURE: harness.py EX-b
NOTES:
```
- The EC-01 patch hardened the **cached-server** side against missing components but left the
  **search-server** side assuming the caller's SPN always contains a `/`:
  `server.upper().split('/')[1]` (ccache.py:458, 459, 466). If `getCredential` is called with
  a no-slash target (e.g. a bare `host@REALM` or `user@REALM`) **and** the cache contains any
  slash-bearing credential, the anySPN loop raises IndexError on master.
- Reachability: `CCache.parseFile` builds `principal = '<target>@<domain>'` from a caller
  `target` (ccache.py:660). Every in-tree caller currently passes a full SPN or `krbtgt/…`
  (both contain `/`), so the primary tools are not currently exposed. But `getCredential` is
  public API used by external tooling and by `examples/getST.py:184` with default
  `anySPN=True`; any caller passing a no-slash target trips it. Recommend the same defensive
  guard (`len(parts) > 1` / `count('/')`) on the search side.
- Minor footnote (not a parser bug): truthiness-testing a *partially populated* `Credential`
  (`if cred:`) invokes `__len__` → `getData` → `pack None`. Real loaded credentials are fully
  populated so this is latent, but callers should test `is not None`, not truthiness.

---

## Cross-file assumption sweep (krb5 subsystem)

`grep -rn "split(b'/')\[1\]|split('/')\[1\]|split('@')\[1\]"` over `impacket/krb5/` returns
matches **only** in `ccache.py::getCredential` (lines 457–466). The unconditional-index SPN
pattern is not duplicated in `kerberosv5.py`, `kpasswd.py`, `types.py`, etc. `kpasswd.py:363`
calls `getCredential(principal, False)` (anySPN disabled → never enters the fragile loop). The
`six.b()` latin-1 assumption (EC-04), by contrast, **is** systemic across the codebase; commit
8ea54fe modernized several modules but left `ccache.py` and the principal-encoding path on the
latin-1 behavior.

## Recommendations (for the fix workstream, not this attack pass)

1. **EC-R (residual crash):** add the same length guard on the search-server side of
   `getCredential`. Same bug class as the one #2242 was opened for; still live on master.
2. **EC-04 (HIGH):** normalize principal components to **UTF-8** (not `six.b()`/latin-1) on
   both encode and compare; decode ccache bytes as UTF-8. Add fixtures with accented and
   non-latin-1 names to `tests/misc/test_ccache.py`.
3. **EC-06 (HIGH):** have the selection layer (or its callers) skip expired tickets and honour
   a required-flags argument, or at minimum expose endtime/flags so callers can filter.
4. **EC-03 (medium):** allow the no-slash branch to match user principals, or document that
   anySPN only resolves machine-account S4U2Self STs.
