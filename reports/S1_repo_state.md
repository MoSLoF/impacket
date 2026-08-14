# S1 — Repo State Determination (for Session 2)

**Project:** iHBV-TM-022 — depSNORT supply-chain assessment
**Target:** `MoSLoF/impacket` (fork)
**Date:** 2026-08-14
**Prepared by:** Session 1 (static supply-chain assessment)

---

## Scope note

This record contains **objective, public git facts only**. Session 1 does not
construct exploits, patches, or offensive tooling, and does not clear any
follow-on offensive activity. Where a question cannot be answered from the
checkout available in this session, it is recorded as **indeterminate** with
the reason — not guessed. If Session 2 intends adversarial work against the
Kerberos ccache subsystem, that work stands on its own authorization and is
outside anything determined or endorsed here.

---

## Structured determination

```
REPO STATE DETERMINATION (for Session 2)
impacket HEAD commit:        4c09897a8645818e873787f2c79ec1bce90c5777 (4c09897)
impacket_0_13_1 tag present: no  (see caveat — shallow clone, tags not fetched)
master ahead of 0.13.1:      indeterminate  (0.13.1 tag not in this checkout)
ccache.py changed since 0.13.1: indeterminate  (0.13.1 tag not in this checkout)
EC-01 fix status:            indeterminate  (EC-01 is a Session-2-internal label
                                             not defined in Session 1 materials;
                                             not mapped to a commit here)
```

## Why the tag-relative fields are indeterminate

The working checkout is a **shallow clone (`git rev-parse --is-shallow-repository` = `true`,
50 commits, `git tag` returns 0 tags)**. No tags were fetched, so
`impacket_0_13_1` is absent **as a clone artifact** — this is *not* evidence
that the upstream fork lacks the tag, and it is *not* evidence that master is
or isn't ahead of 0.13.1. Any "master vs 0.13.1" or "ccache.py since 0.13.1"
answer derived from this checkout would be an artifact of the shallow fetch,
not a real determination. Recorded as indeterminate accordingly.

### How to make these fields determinate (for the operator / Session 2)

```bash
git fetch --unshallow origin           # or: git fetch --tags --depth=1000 origin
git tag | grep 0_13_1                   # confirm the tag exists in the fork
git log impacket_0_13_1..HEAD --oneline # master-ahead determination
git log impacket_0_13_1..HEAD -- impacket/krb5/ccache.py --oneline
```

## Objective facts about `impacket/krb5/ccache.py` on this HEAD

The file exists (32,733 bytes). The most recent commits touching it that are
reachable from HEAD on this branch are:

```
243d64a Fix IndexError in CCache.getCredential when handling 3-part SPNs in
        multi domain forests (e.g. dumped LDAP tickets using rubeus dump
        module) (#2242)
bbbc912 Check cached TGT matches requested user in getST.py (#2218)
c779bb3 Fix AttributeError when parsing a credential with auth data (#2219)
f1cb361 GetUserSPNs.py - Added a switch not to force RC4-HMAC when requesting
        a TGT (#2141)
```

These are upstream impacket commit subjects present on this fork's HEAD. They
are recorded so an operator can map an internal "EC-01" label to a real commit
themselves; Session 1 does not assert that any of them is or is not "EC-01".

## Note on the EC-01 label

"EC-01" and the "present on master / not present — manual patch required"
framing come from the Session 2 brief, not from the repository. Session 1 was
given no definition of the vulnerability EC-01 denotes, so it cannot and does
not determine fix status. If EC-01 corresponds to a published advisory or a
specific upstream commit, resolve it against a full (un-shallow) clone using
the commands above before relying on any patch-status claim.
