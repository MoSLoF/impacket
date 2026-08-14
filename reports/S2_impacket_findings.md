# S2 — impacket ccache Adversarial Findings (TM-022 Wave 1)

**Subsystem under test:** `impacket/krb5/ccache.py` — `CCache.getCredential()` SPN
matching and its callers.
**Assessment date:** 2026-08-14
**Fork:** `MoSLoF/impacket`
**Working branch:** `claude/impacket-ccache-adversarial-ggyjdd`

---

## 0. Repo state determination (S1 prerequisite not found)

The prerequisite `reports/S1_repo_state.md` **does not exist** anywhere in this
fork's tree or history (`git log --all`, working tree, and stash all checked).
No `depSNORT` / supply-chain artifact is present either. Rather than fabricate a
missing input, the repo state was determined directly from git:

| Role | Commit | Meaning |
|------|--------|---------|
| **patched** (branch HEAD) | `4c09897a8645818e873787f2c79ec1bce90c5777` | contains the fix |
| **fixing commit** | `243d64a67599e24a1c5dd7eb3ff8667d2d5bc2fc` (#2242) | 3-part SPN fix |
| **baseline** (`fix^`) | `2dae5c7f27cff3c95bf44d1ef93ff84e5b380b82` | pre-fix, 0.13.1-era |

This maps to the setup guide's **"master is ahead of 0.13.1 and ccache.py has
changed (fix present)"** branch. The pre-fix baseline was materialised with
`git worktree add /tmp/impacket-prefix 243d64a^`. Module isolation was verified
from a neutral cwd — the harness prints the resolved `ccache.__file__` for each
version on every run:

```
# baseline  ccache: /tmp/impacket-prefix/impacket/krb5/ccache.py
# patched   ccache: /home/user/impacket/impacket/krb5/ccache.py
```

No VC-001 block condition was inherited (no S1 to inherit from) and nothing in
the dependency tree flagged as malicious during dependency install
(`pyasn1`, `six`, `pycryptodomex`). Assessment proceeded.

> "master" is deliberately **not** used as a version reference below. Every
> finding cites the two commit hashes above.

---

## 1. The fix under test (#2242)

`CCache.getCredential(server, anySPN=True)` has two phases:

1. **Exact-match loop** — string-equality on `server` (and `@`-stripped forms).
   Never crashes; returns the first exact match.
2. **anySPN fallback loop** (only when phase 1 misses) — tries to match "any
   TGT/TGS for the same host, ignoring service class / port". This loop is where
   every finding below lives.

Pre-fix, the fallback had two branches keyed on `find(b'/') >= 0`. The `/`-branch
built a comparison SPN with a hard positional index:

```python
cachedSPN = (...split(b'/')[1].split(b'@')[0].split(b':')[0]
             + b'@' + ...split(b'/')[1].split(b'@')[1])   # <-- [1] assumes '@'
```

For a 3-part SPN `LDAP/host/domain@REALM`, `split(b'/')[1]` is the **host**
(`host`), which contains no `@` — so `.split(b'@')[1]` raises `IndexError`. The
fix (#2242) adds a leading `count(b'/') >= 2` branch that parses 3-part SPNs
explicitly (host from `parts[1]`, realm from `parts[-1]`, port stripped via
`split(b':', 1)[0]`), with short-name/FQDN matching.

---

## 2. Differential results (one line per fixture)

Produced by `tm022_wave1_harness/harness.py` (EC-01/02/03/05 + EC-R),
`ec04.py` (EC-04), `ec06.py` (EC-06). `crash` = `IndexError`; `correct` = matched
as expected / clean `None`; `silent-wrong-result` = wrong ticket, no exception.

| Case | Fixture | Baseline `2dae5c7` | Patched `4c09897` | Δ |
|------|---------|--------------------|-------------------|---|
| EC01-direct | search a 3-part cached SPN | **crash** | correct | fixed |
| EC01-poison | 3-part poisons a following anySPN lookup | **crash** | correct | fixed |
| EC01-target-poison | parseFile-style target lookup past a 3-part SPN | **crash** | correct | fixed |
| EC01-empty-third | `LDAP/host/@REALM` | correct¹ | correct¹ | same |
| EC01-fourpart | `LDAP/host/extra/domain@REALM` | **crash** | correct | fixed |
| EC02-referral | `krbtgt/CHILD@PARENT` exact | correct | correct | same |
| EC02-referral-anyspn | referral TGT via anySPN | correct² | correct² | same |
| EC03-machine | `WS01$@REALM` matches `cifs/ws01.fqdn@REALM` | correct | correct | same |
| EC03-user | user principal S4U2Self | correct³ | correct³ | same |
| EC05-2part-port | `HTTP/web:8443@REALM` | correct | correct | same |
| EC05-3part-port | `LDAP/dc:3268/domain@REALM` | **crash** | correct | fixed |
| **EC-R** | **no-slash *search* SPN vs slash cache** | **crash** | **crash** | **same — residual** |
| EC-04 | Cyrillic principal/realm | crash⁴ | crash⁴ | same |
| EC-06 | expired-first same-SPN cache | **silent-wrong-result** | **silent-wrong-result** | same |

¹ Empty 3rd component is **normalised away at the `types.Principal` layer**
(`LDAP/dc.lab.local/@LAB.LOCAL` → 2-part `LDAP/dc.lab.local@LAB.LOCAL`); it never
reaches the 3-part branch on either version.
² By the anySPN contract (match any service on that host+realm). Semantic note in EC-02.
³ Clean `None`; the "silent miss" nuance is discussed in EC-03.
⁴ `UnicodeEncodeError`, not `IndexError` — different failure class. See EC-04.

---

## 3. Findings

### EDGE CASE: EC-01 — 3-part SPN in the anySPN fallback
```
SPEC BASIS: MS-KILE §2.2 / RFC 4120 §6.2. service/host/domain SPNs are spec-legal
            and produced by Windows when a service ticket is cached with the
            domain suffix appended (e.g. Rubeus `dump` in a multi-domain forest).
VERSIONS TESTED:
  baseline: 2dae5c7 (pre-fix, 0.13.1-equivalent)
  patched:  4c09897 (branch HEAD, contains fix 243d64a / #2242)
FILES AFFECTED: impacket/krb5/ccache.py  (getCredential anySPN loop)
OUTCOME baseline: crash (IndexError, split(b'@')[1] on a host component)
OUTCOME patched:  correct
SAME ASSUMPTION ELSEWHERE: yes — the search-side of the same branch (see EC-R)
FIXTURE: tm022_wave1_harness/harness.py :: EC01-direct / EC01-poison /
         EC01-target-poison / EC01-fourpart
OPERATIONAL NOTE:
  Confirmed the poisoning claim empirically. The crash lives in the anySPN
  fallback, which runs only when the exact-match loop misses. So the trigger is
  not "a 3-part ticket is present" but "a lookup falls through to anySPN while a
  3-part ticket is earlier in iteration order." That is the common case:
  parseFile() (line ~661) issues getCredential('<target>@<domain>', anySPN=True)
  for a target that is frequently not stored verbatim (short-name vs FQDN,
  service casing). One dumped LDAP ticket anywhere earlier in the cache then
  IndexErrors the entire lookup — cifs/ldap/mssql auth via -k -no-pass all break
  mid-engagement, not just the LDAP path. The fix resolves every crashing
  permutation tested (3-part, 4-part, 3-part-with-port). Empty-3rd-component is a
  non-issue: types.Principal drops the empty label before the SPN ever reaches
  this code.
```

### EDGE CASE: EC-02 — Cross-realm referral TGT
```
SPEC BASIS: RFC 4120 §3.3.3. krbtgt/CHILD.REALM@PARENT.REALM — a 2-part SPN whose
            SECOND component is a realm, not a hostname.
VERSIONS TESTED: baseline 2dae5c7 / patched 4c09897
FILES AFFECTED: impacket/krb5/ccache.py
OUTCOME baseline: correct   OUTCOME patched: correct
SAME ASSUMPTION ELSEWHERE: n/a
FIXTURE: tm022_wave1_harness/harness.py :: EC02-referral / EC02-referral-anyspn
OPERATIONAL NOTE:
  Exact-match lookup of a referral TGT works. Via the anySPN fallback, a search
  for HOST/CHILD.LAB.LOCAL@LAB.LOCAL returns the referral krbtgt, because the loop
  matches on 2nd-component + realm and cannot distinguish "realm in host position"
  from a real host. This is the documented anySPN contract (match any service on
  that name), so it is not a defect — but it is a latent semantic conflation: in a
  forest where a host literally shares a name with a child realm label, anySPN
  could hand back a referral TGT where a service ticket was intended. No crash,
  no version delta. Recorded as a design note, not a bug.
```

### EDGE CASE: EC-03 — S4U2Self ST with no service type
```
SPEC BASIS: MS-SFU §3.2.5.1.2. The no-slash fallback branch assumes 'hostname$@REALM'.
VERSIONS TESTED: baseline 2dae5c7 / patched 4c09897
FILES AFFECTED: impacket/krb5/ccache.py  (else-branch, line ~465)
OUTCOME baseline: correct   OUTCOME patched: correct
SAME ASSUMPTION ELSEWHERE: the else-branch ALSO does server.split('/')[1] on the
            SEARCH string (line ~466) — same root cause as EC-R.
FIXTURE: tm022_wave1_harness/harness.py :: EC03-machine / EC03-user
OPERATIONAL NOTE:
  Machine-account match works: cache 'WS01$@REALM' is correctly returned for a
  search 'cifs/ws01.fqdn@REALM' (short-name + '$' synthesis). A *user* principal
  with no trailing '$' (cache 'administrator@REALM') can never match via this
  branch — it hard-codes the '$' machine-account suffix, so the comparison is
  'ADMINISTRATOR@REALM' == 'ADMINISTRATOR$@REALM' → always False → silent miss.
  This is a silent-wrong-result *shape* (no exception, just "not found"), but it
  is correct-by-design for the machine-account tickets this branch targets; a
  slash-less user principal in the server field is not a normal S4U2Self ST.
  Flagged low-severity, identical on both versions. The branch's real exposure is
  the shared search-side split (EC-R), not the '$' assumption.
```

### EDGE CASE: EC-04 — Non-ASCII (UTF-8) principal / realm
```
SPEC BASIS: RFC 4120 §5.2.1 (IA5String) extended by MS-KILE (UTF-8 in practice).
VERSIONS TESTED: baseline 2dae5c7 / patched 4c09897
FILES AFFECTED: impacket/krb5/ccache.py (getCredential line 420; Principal.prettyPrint
            line ~164/173), via six.b().
OUTCOME baseline: crash (UnicodeEncodeError)   OUTCOME patched: crash (identical)
SAME ASSUMPTION ELSEWHERE: every six.b() call on principal-derived strings.
FIXTURE: tm022_wave1_harness/ec04.py
LAYER LOCALISATION (per-layer probe, both versions identical):
  cifs/café.lab.local@LAB.LOCAL   (é ∈ Latin-1):  ok at every layer.
  cifs/СЕРВЕР@ДОМЕН.LOCAL (Cyrillic):
    six.b            -> UnicodeEncodeError  <-- origin
    types.Principal  -> ok   (pure str splitting, no encode)
    fromPrincipal    -> ok   (stores str into CountedOctetString unchanged)
    prettyPrint      -> UnicodeEncodeError  (b(component['data']) re-encodes latin-1)
    getCredential    -> UnicodeEncodeError  (first line b(server.upper()))
OPERATIONAL NOTE:
  The failure originates at six.b() == s.encode("latin-1"), which is narrower than
  the UTF-8 MS-KILE puts on the wire. Anything above U+00FF (Cyrillic, CJK, emoji)
  hard-crashes; accented names inside Latin-1 survive. Neither #2242 nor #2243
  ("Modernize byte string normalization") touches this path — confirmed identical
  on both commits. Mid-engagement impact: any op against a non-Latin-1 realm
  (common in RU/CN/JP estates) crashes at cache-read time, independent of EC-01.
  This is a pre-existing, separate defect from the 3-part SPN class and is out of
  scope for the #2242 fix; recorded so it is not mistaken for a regression.
```

### EDGE CASE: EC-05 — Port specifier in SPN
```
SPEC BASIS: MS-KILE SPN grammar: serviceclass "/" hostname [":" port] ["/" servicename]
VERSIONS TESTED: baseline 2dae5c7 / patched 4c09897
FILES AFFECTED: impacket/krb5/ccache.py
OUTCOME baseline: 2-part+port correct; 3-part+port CRASH
OUTCOME patched:  both correct
SAME ASSUMPTION ELSEWHERE: n/a (fix uses split(b':',1)[0] consistently)
FIXTURE: tm022_wave1_harness/harness.py :: EC05-2part-port / EC05-3part-port
OPERATIONAL NOTE:
  A port in a 2-part SPN (HTTP/web:8443@REALM) was already stripped correctly
  pre-fix (the old branch's split(b':')[0]). A port in a 3-part SPN
  (LDAP/dc:3268/domain@REALM) crashed on baseline — because the *3-part* shape
  crashed regardless of the port. The fix handles the full matrix: its
  split(b':', 1)[0] strips the port on the host component whether the SPN is 2- or
  3-part. No residual gap on the port dimension.
```

### EDGE CASE: EC-06 — Mixed / expired ticket flags
```
SPEC BASIS: RFC 4120 §5.3 (endtime / renew-till) and §2 (TicketFlags).
VERSIONS TESTED: baseline 2dae5c7 / patched 4c09897
FILES AFFECTED: impacket/krb5/ccache.py (getCredential selection layer)
OUTCOME baseline: silent-wrong-result   OUTCOME patched: silent-wrong-result (identical)
SAME ASSUMPTION ELSEWHERE: the entire selection layer — getCredential never reads
            time.endtime or tktflags.
FIXTURE: tm022_wave1_harness/ec06.py
OPERATIONAL NOTE:
  With two credentials for the SAME server principal, getCredential returns the
  FIRST match in storage order — verified by symmetry: expired-first returns the
  expired/non-forwardable ticket (idx 0); valid-first returns the valid one (idx 0).
  Selection is order-dependent, not quality-dependent. There is no expiry check and
  no forwardable check in the selection layer. This is the highest-priority *shape*
  in this report: a crash is loud and aborts; this hands back a dead or
  non-forwardable ticket silently, and the failure resurfaces later as
  KRB_AP_ERR_TKT_EXPIRED at use time or a delegation that cannot forward — far from
  the ccache read that caused it. Identical on both versions; entirely outside the
  #2242 fix's scope.
```

### EDGE CASE: EC-R — Residual: no-slash SEARCH SPN (FIRST-CLASS, unfixed on patched)
```
SPEC BASIS: same as EC-01. A search SPN with no '/' is a spec-legal principal
            (e.g. 'HOST@REALM', 'user@REALM', a bare hostname@domain target).
VERSIONS TESTED: baseline 2dae5c7 / patched 4c09897
FILES AFFECTED: impacket/krb5/ccache.py
  line 458 (2-part branch):  server.upper().split('/')[1]   <-- crashes
  line 442 (3-part branch):  server.upper().split('/')[serverParts[1]] <-- same class
  line 466 (no-slash branch): server.upper().split('/')[1]  <-- same class
OUTCOME baseline: crash (IndexError)   OUTCOME patched: crash (IndexError, line 458)
SAME ASSUMPTION ELSEWHERE: yes — all THREE anySPN branches assume the *search*
            string contains a '/'. The #2242 fix hardened the cached-server side
            only; the search-server side retains the original assumption.
FIXTURE: tm022_wave1_harness/harness.py :: ECR-noslash-search
REPRODUCTION (patched HEAD):
  c = CCache(); c.credentials.append(<cred for 'cifs/fs.lab.local@LAB.LOCAL'>)
  c.getCredential('fs.lab.local@LAB.LOCAL')   # no slash in search
  -> IndexError at ccache.py:458  (server.upper().split('/')[1])
  c.getCredential('fs.lab.local@LAB.LOCAL', anySPN=False)   # immune (fallback skipped)
  -> None
OPERATIONAL NOTE:
  Promoted to a first-class finding per the EC-R directive: the vendor fix closed
  the cached-server 3-part crash but the symmetric search-server crash survives on
  patched HEAD. Reachability through *shipped* code is currently LOW: every stock
  parseFile() caller prefixes a service class — smbconnection ('cifs/%s'),
  ldap/ldap.py & examples/utils.py ('ldap/%s') — so the search string always has a
  slash. It is reachable directly through the public API
  CCache.getCredential(server, anySPN=True) whenever `server` has no '/' and any
  slash-bearing ticket is in the cache with no exact match — i.e. third-party
  tooling using impacket as a library, or a future caller passing a bare
  hostname/user target. Classify as a latent / defense-in-depth residual of the
  exact same class the maintainers already accepted in #2242.
  One-line fix of the same shape as the accepted patch — guard before indexing:
      if '/' not in server: continue   # or count-based guard, mirroring count(b'/')
  applied at the top of the anySPN loop body, so a slash-less search SPN is skipped
  rather than IndexError-ing the whole cache walk. anySPN=False is already immune.
```

---

## 4. "Same assumption, different file" — krb5 subsystem sweep

```
$ grep -rn "split(b'/')\[1\]\|split('/')\[1\]\|split(b'@')\[1\]\|split('@')\[1\]" impacket/krb5/
impacket/krb5/ccache.py:457  cachedSPN = ...split(b'/')[1]...split(b'@')[1]   # cached, 2-part (fixed path retained for 1-slash)
impacket/krb5/ccache.py:458  searchSPN = ...server.upper().split('/')[1]...   # SEARCH side  -> EC-R
impacket/krb5/ccache.py:459                     ...server.upper().split('/')[1].split('@')[1]
impacket/krb5/ccache.py:465  cachedSPN = ...split(b'@')[1]                    # cached, no-slash branch
impacket/krb5/ccache.py:466  searchSPN = ...server.upper().split('/')[1]...   # SEARCH side  -> EC-R
```

All hits are inside `getCredential`. The positional-index assumption exists on
**both** the cached side (largely hardened by #2242 for the 3-part case) and the
**search side** (unhardened — EC-R). No other file in `impacket/krb5/` repeats the
`split(...)[1]` pattern against externally-controlled principal strings. `kpasswd.py`
calls `getCredential(principal, False)` with `anySPN=False`, so it never enters the
fallback loop and is immune to both EC-01 and EC-R.

---

## 5. Verdict on the #2242 fix

- **Resolves** EC-01 in every crashing permutation tested (3-part, 4-part,
  3-part-with-port) and passes its own regression assertions on patched HEAD
  (verified directly, `pytest` unavailable in-env — the three `#2242` assertions
  were replayed under `unittest`-free harnessing and all pass).
- **No regression** introduced: every case that was `correct` on baseline remains
  `correct` on patched (EC-02, EC-03, EC-05-2part, and the Latin-1 EC-04 leg).
- **Does not address** three pre-existing, out-of-class issues, all identical on
  both versions and none a regression: EC-06 (order-dependent selection,
  silent-wrong-result — highest priority), EC-04 (Latin-1-only normalization),
  and EC-R (symmetric search-side crash of the *same* class the fix hardened on
  the cached side — the one residual worth a follow-up one-line guard).

**Priority ranking for follow-up (silent-wrong-result outranks crash):**
1. **EC-06** — silent expired/non-forwardable ticket selection (no expiry/flag check).
2. **EC-R** — search-side no-slash `IndexError`, same class as the accepted fix.
3. **EC-04** — non-Latin-1 realm hard-crash (separate byte-normalization defect).

EC-02 / EC-03 are design notes, not defects.
