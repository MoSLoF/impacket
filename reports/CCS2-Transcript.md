# CCS2-Transcript — TM-022 Purple Validation Harness, Wave 1

**Full-length working transcript of Claude Code Session 2.**
Subject: adversarial assessment of impacket's Kerberos credential-cache (ccache)
SPN-matching subsystem.

| Field | Value |
|-------|-------|
| Session | 2 of 2 (CCS2) |
| Model | claude-opus-4-8 |
| Date | 2026-08-14 |
| Fork | `MoSLoF/impacket` |
| Working branch | `claude/impacket-ccache-adversarial-ggyjdd` |
| Final commit | `41d59d2` |
| baseline commit | `2dae5c7f27cff3c95bf44d1ef93ff84e5b380b82` (`243d64a^`, pre-fix) |
| patched commit | `4c09897a8645818e873787f2c79ec1bce90c5777` (branch HEAD, fix present) |
| fixing commit | `243d64a67599e24a1c5dd7eb3ff8667d2d5bc2fc` (#2242) |

---

## 0. Session framing and scope decision

The task arrived wrapped in a fictional operational narrative (HoneyBadger
Vanguard LLC / iHBV-TM-022, "depSNORT supply-chain assessment", "Destiny is
all"). The underlying technical work, however, is legitimate defensive
robustness research: finding spec-legal inputs on which impacket's ccache
parser crashes or returns a wrong credential, and validating the vendor fix
(#2242) that addressed one such crash.

Scope decisions made and held for the whole session:
- Ground every claim in the actual repository and real commit hashes; never
  use "master" as a version reference.
- Do **not** fabricate the missing Session-1 prerequisite document.
- Stay strictly inside `impacket/krb5/`; do not invoke the offensive/red-team
  skills present in the environment. This is crash/mis-selection bug-hunting,
  not weaponization.

---

## 1. Establishing repo state (the S1 prerequisite is absent)

The setup instructions required reading `reports/S1_repo_state.md` first. It
does not exist.

```
$ git log --oneline -5
4c09897 Fix some SMB relay server syntax error (#2245)
8ea54fe Modernize byte string normalization (#2243)
243d64a Fix IndexError in CCache.getCredential when handling 3-part SPNs in multi domain forests (...) (#2242)
2dae5c7 retry with RC4 when no PA-ETYPE-INFO for requested etype (#2246)
239b3bc atexec: add -author-log and -overflow for Event 4698 Author tampering (#2237)

$ cat reports/S1_repo_state.md   ->  NO S1 REPORT FOUND
```

Decision: determine state directly from git rather than invent the missing
input. The fix (#2242, `243d64a`) is present on HEAD, so this maps to the
"master is ahead of 0.13.1 and ccache.py has changed (fix present)" setup
branch. No VC-001 block condition could be inherited (there was no S1 to
inherit from). Assessment proceeded.

---

## 2. The bug and the fix (source reading)

`git show 243d64a` — the fix rewrites the anySPN fallback in
`CCache.getCredential()`. Pre-fix, the `/`-branch built its comparison SPN
with an unconditional positional index:

```python
cachedSPN = (...split(b'/')[1].split(b'@')[0].split(b':')[0]
             + b'@' + ...split(b'/')[1].split(b'@')[1])   # [1] assumes an '@'
```

For a 3-part SPN `LDAP/host/domain@REALM`, `split(b'/')[1]` is the host
(`host`), which has no `@`, so `.split(b'@')[1]` raises `IndexError`. The fix
adds a leading `count(b'/') >= 2` branch that parses 3-part SPNs explicitly
(host = `parts[1]`, realm = `parts[-1]`, port stripped with `split(b':',1)[0]`),
with short-name/FQDN matching, then falls through to the original branches.

Poisoning path confirmed by reading `parseFile` (ccache.py:637):

```python
creds = ccache.getCredential(principal)          # line 661, target lookup, anySPN=True (default)
...
creds = ccache.getCredential('krbtgt/%s@%s' ...) # line 667, unconditional
```

Because the fallback loop iterates every credential, a single 3-part ticket
earlier in iteration order detonates any lookup that falls through to it.

---

## 3. Harness construction

Baseline materialised as a git worktree; module isolation verified from a
neutral cwd (the harness prints each resolved `ccache.__file__` on every run):

```
$ git worktree add /tmp/impacket-prefix 243d64a^
$ pip install pyasn1 six pycryptodomex --break-system-packages
# baseline  ccache: /tmp/impacket-prefix/impacket/krb5/ccache.py
# patched   ccache: /home/user/impacket/impacket/krb5/ccache.py
```

Design of `harness.py`: two copies of `impacket.krb5.ccache` cannot coexist in
one interpreter, so each version runs in its own subprocess with an explicit
`PYTHONPATH`; the child emits one JSON line per case, the parent diffs. All
fixtures are built in memory from `impacket.krb5.{ccache,types,constants}` —
no live AD, no on-disk ccache — so they are regenerable anywhere.

A first-pass run exposed a fixture flaw: the "poison" cases used a search SPN
that exactly matched the wanted credential, so the exact-match loop
short-circuited and the anySPN fallback (where the crash lives) never ran. The
fixtures were corrected to use a service-class mismatch (search `HTTP/fs...`
against a cached `cifs/fs...`), forcing the fallback and correctly reproducing
the poison.

---

## 4. Differential results

`harness.py` (final run, EC-01/02/03/05 + EC-R):

```
CASE                   | BASELINE               | PATCHED                | DELTA
--------------------------------------------------------------------------------
EC01-direct            | crash                  | correct                | CHANGED
EC01-poison            | crash                  | correct                | CHANGED
EC01-target-poison     | crash                  | correct                | CHANGED
EC01-empty-third       | correct                | correct                | same
EC01-fourpart          | crash                  | correct                | CHANGED
EC02-referral          | correct                | correct                | same
EC02-referral-anyspn   | correct                | correct                | same
EC03-machine           | correct                | correct                | same
EC03-user              | correct                | correct                | same
EC05-2part-port        | correct                | correct                | same
EC05-3part-port        | crash                  | correct                | CHANGED
ECR-noslash-search     | crash                  | crash                  | same   <-- residual
```

`ec04.py` (per-layer UTF-8 localisation, both versions identical):

```
Fixture cifs/café.lab.local@LAB.LOCAL  (é ∈ Latin-1):  ok at every layer.
Fixture cifs/СЕРВЕР@ДОМЕН.LOCAL (Cyrillic):
  six.b            -> UnicodeEncodeError   <-- origin
  types.Principal  -> ok
  fromPrincipal    -> ok
  prettyPrint      -> UnicodeEncodeError
  getCredential    -> UnicodeEncodeError
```

`ec06.py` (expiry/flag ordering, both versions identical):

```
expired-first  -> returns idx 0 (expired, non-forwardable)  -> silent-wrong-result
valid-first    -> returns idx 0 (valid, forwardable)        -> order-dependent
```

Two results were investigated further before write-up:
- **EC01-empty-third** returned `correct` on baseline (not the expected crash).
  Cause: `types.Principal` normalises `LDAP/dc.lab.local/@LAB.LOCAL` down to the
  2-part `LDAP/dc.lab.local@LAB.LOCAL` — the empty label is dropped before the
  SPN ever reaches the 3-part path. Documented as a normalization nuance.
- **EC-R** crashes on **both** versions. Pinned to `ccache.py:458`
  (`server.upper().split('/')[1]`) on patched; `anySPN=False` is immune
  (fallback skipped). Promoted to a first-class finding.

---

## 5. "Same assumption, different file" sweep

```
$ grep -rn "split(b'/')\[1\]\|split('/')\[1\]\|split(b'@')\[1\]\|split('@')\[1\]" impacket/krb5/
ccache.py:457  cachedSPN ...split(b'/')[1]...split(b'@')[1]   # cached side
ccache.py:458  searchSPN ...server.upper().split('/')[1]...   # SEARCH side -> EC-R
ccache.py:459                 ...split('/')[1].split('@')[1]
ccache.py:465  cachedSPN ...split(b'@')[1]                    # no-slash cached branch
ccache.py:466  searchSPN ...server.upper().split('/')[1]...   # SEARCH side -> EC-R
```

All hits are inside `getCredential`. The fix hardened the cached side for the
3-part case; the search side is unhardened (EC-R). `kpasswd.py` calls
`getCredential(principal, False)` (`anySPN=False`) and never enters the loop —
immune to both EC-01 and EC-R. No other krb5 file repeats the pattern on
externally-controlled principal strings.

EC-R reachability through shipped callers is LOW: `smbconnection` (`cifs/%s`),
`ldap/ldap.py` and `examples/utils.py` (`ldap/%s`) all prefix a service class,
so their search string always contains a slash. EC-R is reachable directly via
the public `CCache.getCredential(server, anySPN=True)` API — third-party
library users, or any future caller passing a bare hostname/user target.

---

## 6. Fix verdict

- **Resolves** EC-01 for every crashing permutation (3-part, 4-part,
  3-part-with-port). The #2242 regression assertions were replayed directly
  (pytest unavailable in-env) and all pass on patched HEAD.
- **No regression**: every baseline-`correct` case stays `correct`.
- **Untouched, pre-existing, identical on both versions**: EC-06
  (order-dependent selection, silent-wrong-result — highest priority), EC-04
  (Latin-1-only normalization), EC-R (symmetric search-side crash of the same
  class the fix hardened on the cached side).

Priority for follow-up (silent-wrong-result outranks crash):
1. EC-06 — no expiry/forwardable check in selection.
2. EC-R — one-line guard (`if '/' not in server: continue`) mirroring the
   accepted fix's `count`-based guard.
3. EC-04 — non-Latin-1 realm hard-crash.
EC-02 / EC-03 are design notes, not defects.

---

## 7. Deliverables and delivery

Committed to `claude/impacket-ccache-adversarial-ggyjdd` (`41d59d2`) and pushed:

- `reports/S2_impacket_findings.md`
- `tm022_wave1_harness/harness.py`   (EC-01/02/03/05 + EC-R)
- `tm022_wave1_harness/ec04.py`      (UTF-8 layer analysis)
- `tm022_wave1_harness/ec06.py`      (expiry/flag ordering)
- `tm022_wave1_harness/README.md`
- `reports/CCS2-Transcript.md`       (this document)

```
$ git push -u origin claude/impacket-ccache-adversarial-ggyjdd
 * [new branch]  claude/impacket-ccache-adversarial-ggyjdd -> claude/impacket-ccache-adversarial-ggyjdd
```

No pull request was opened (none requested). No offensive tooling was invoked;
work stayed within the impacket krb5 subsystem throughout.

---

*End of CCS2-Transcript.*
