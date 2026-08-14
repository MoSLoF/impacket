#!/usr/bin/env python3
"""
TM-022 Wave 1 — Differential fixture harness for impacket's Kerberos
credential-cache (ccache) SPN-matching logic.

Covers EC-01, EC-02, EC-03, EC-05 (crash / correctness cases that live inside
CCache.getCredential's anySPN fallback loop).  EC-04 (UTF-8 layering) and EC-06
(expiry/flag ordering) live in ec04.py and ec06.py respectively.

WHY A SUBPROCESS RUNNER
-----------------------
The whole point of this harness is a *differential*: run identical fixtures
against the pre-fix baseline and the patched tree and diff the outcomes.  Two
copies of `impacket.krb5.ccache` cannot coexist in one interpreter, so each
version is exercised in its own subprocess with an explicit PYTHONPATH.  The
child prints a single JSON line per case; the parent diffs them.

USAGE
-----
    python3 harness.py --baseline /tmp/impacket-prefix --patched /home/user/impacket

If invoked with --child <case_id>, the process runs one case in-process and
emits JSON — this is the subprocess entrypoint and is not meant to be called
by hand.
"""
import argparse
import json
import os
import subprocess
import sys


# --------------------------------------------------------------------------
# Fixture construction (runs inside the child, against whichever ccache is on
# the PYTHONPATH).  Kept dependency-light: only impacket.krb5.{ccache,types,
# constants} are touched, so a fixture built here is regenerable anywhere the
# library imports.
# --------------------------------------------------------------------------
def _build_env():
    from impacket.krb5 import ccache, types, constants

    def make_cred(spn_string, name_type=None):
        """Construct a Credential whose 'server' Principal is `spn_string`.

        name_type defaults to NT_SRV_INST (2), matching how service tickets are
        stored.  The value is irrelevant to getCredential's string matching but
        we set it faithfully so fixtures mirror real caches.
        """
        if name_type is None:
            name_type = int(constants.PrincipalNameType.NT_SRV_INST.value)
        cred = ccache.Credential()
        principal = ccache.Principal()
        p = types.Principal(spn_string, type=name_type)
        principal.fromPrincipal(p)
        cred['server'] = principal
        return cred

    return ccache, types, constants, make_cred


# --------------------------------------------------------------------------
# Case table.  Each case returns (cache, search_spn, description).
# A case is "correct" if getCredential returns the credential we expect
# (or None when we expect a miss); it is a "crash" if getCredential raises;
# it is "silent-wrong-result" if it returns the wrong credential.
#
# Each entry declares `expect`:
#   ('match', idx)  -> expect getCredential to return cache.credentials[idx]
#   ('none',)       -> expect getCredential to return None (clean miss)
# The child compares the actual result against this and classifies the outcome.
# --------------------------------------------------------------------------
def build_case(case_id):
    ccache, types, constants, make_cred = _build_env()

    if case_id == 'EC01-direct':
        # 3-part SPN present; search for it via a 2-part (no-domain-suffix) SPN.
        # Baseline crashes constructing cachedSPN (host component has no '@').
        c = ccache.CCache()
        c.credentials.append(make_cred(
            'LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL'))
        return c, 'LDAP/us-dc.us.techcorp.local@US.TECHCORP.LOCAL', \
            'EC01 direct: search a 3-part cached SPN', ('match', 0)

    if case_id == 'EC01-poison':
        # A 3-part SPN sitting *before* the credential we actually want.
        # To reach the anySPN fallback loop (where the poison lives) the search
        # SPN must NOT exactly match anything: we search HTTP/fs... while the
        # cache holds cifs/fs... (same host+realm, different service class).
        # Exact-match loop misses -> anySPN loop runs -> idx0 (3-part) detonates
        # on baseline before idx1 (cifs) is ever compared.  On patched, idx0 is
        # handled gracefully (host mismatch) and idx1 anySPN-matches on host.
        c = ccache.CCache()
        c.credentials.append(make_cred(
            'LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL'))
        c.credentials.append(make_cred('cifs/fs.lab.local@LAB.LOCAL'))
        return c, 'HTTP/fs.lab.local@LAB.LOCAL', \
            'EC01 poison: 3-part SPN poisons a following anySPN lookup', \
            ('match', 1)

    if case_id == 'EC01-target-poison':
        # Operational reproduction of the parseFile() target path (line ~661):
        # getCredential('<target>@<domain>') with anySPN default True.  A target
        # that is not stored verbatim (short name vs FQDN / service casing)
        # falls through to the anySPN loop; one dumped LDAP 3-part ticket earlier
        # in the cache crashes the whole lookup before the wanted TGS is found.
        c = ccache.CCache()
        c.credentials.append(make_cred(
            'LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL'))
        c.credentials.append(make_cred('cifs/fileserver.lab.local@LAB.LOCAL'))
        return c, 'HOST/fileserver.lab.local@LAB.LOCAL', \
            'EC01 target poison: parseFile-style anySPN lookup past a 3-part SPN', \
            ('match', 1)

    if case_id == 'EC01-empty-third':
        # Empty 3rd component: LDAP/host/@REALM  (count(b'/')>=2 still true).
        c = ccache.CCache()
        c.credentials.append(make_cred('LDAP/dc.lab.local/@LAB.LOCAL'))
        return c, 'LDAP/dc.lab.local@LAB.LOCAL', \
            'EC01 empty 3rd component', ('match', 0)

    if case_id == 'EC01-fourpart':
        # 4-part SPN.  Not standard, but count(b'/')>=2 routes it into the new
        # branch; check it does not crash and matches on host+realm.
        c = ccache.CCache()
        c.credentials.append(make_cred(
            'LDAP/dc.lab.local/extra/lab.local@LAB.LOCAL'))
        return c, 'LDAP/dc.lab.local@LAB.LOCAL', \
            'EC01 4-part SPN routing', ('match', 0)

    if case_id == 'EC02-referral':
        # Cross-realm referral TGT: krbtgt/CHILD.REALM@PARENT.REALM.
        # 2-part SPN whose 2nd component is a realm, not a host.  Search using
        # the same 3-part-ish form a caller would build.
        c = ccache.CCache()
        c.credentials.append(make_cred('krbtgt/CHILD.LAB.LOCAL@LAB.LOCAL'))
        # Exact-match path (first loop) should already catch this:
        return c, 'krbtgt/CHILD.LAB.LOCAL@LAB.LOCAL', \
            'EC02 referral TGT exact', ('match', 0)

    if case_id == 'EC02-referral-anyspn':
        # Force the anySPN fallback: search a HOST SPN whose host component is
        # the referral realm name.  anySPN matches on 2nd-component + realm and
        # cannot tell that the referral TGT's 2nd component is a *realm*, not a
        # host -> it returns the referral krbtgt.  Per the anySPN contract
        # (match any service on that "host"), this is the documented behaviour;
        # the report notes the realm-vs-host semantic conflation.
        c = ccache.CCache()
        c.credentials.append(make_cred('krbtgt/CHILD.LAB.LOCAL@LAB.LOCAL'))
        return c, 'HOST/CHILD.LAB.LOCAL@LAB.LOCAL', \
            'EC02 referral TGT via anySPN fallback (realm-in-host-position)', \
            ('match', 0)

    if case_id == 'EC03-machine':
        # S4U2Self ST with no service type -> 'hostname$@REALM'.
        c = ccache.CCache()
        c.credentials.append(make_cred('WS01$@LAB.LOCAL',
                             name_type=int(constants.PrincipalNameType.NT_PRINCIPAL.value)))
        return c, 'cifs/ws01.lab.local@LAB.LOCAL', \
            'EC03 machine account S4U2Self match', ('match', 0)

    if case_id == 'EC03-user':
        # S4U2Self for a *user* principal (no trailing '$').  The no-slash
        # branch appends '$' to the search host, so a user ST silently misses.
        c = ccache.CCache()
        c.credentials.append(make_cred('administrator@LAB.LOCAL',
                             name_type=int(constants.PrincipalNameType.NT_PRINCIPAL.value)))
        return c, 'cifs/administrator@LAB.LOCAL', \
            'EC03 user account S4U2Self (silent miss check)', ('none',)

    if case_id == 'EC05-2part-port':
        # 2-part SPN with a port: HTTP/web.lab.local:8443@LAB.LOCAL.
        c = ccache.CCache()
        c.credentials.append(make_cred('HTTP/web.lab.local:8443@LAB.LOCAL'))
        return c, 'HTTP/web.lab.local@LAB.LOCAL', \
            'EC05 2-part SPN with port', ('match', 0)

    if case_id == 'EC05-3part-port':
        # 3-part SPN with a port in the host component.
        c = ccache.CCache()
        c.credentials.append(make_cred('LDAP/dc.lab.local:3268/lab.local@LAB.LOCAL'))
        return c, 'LDAP/dc.lab.local@LAB.LOCAL', \
            'EC05 3-part SPN with port', ('match', 0)

    if case_id == 'ECR-noslash-search':
        # EC-R residual: a no-slash *search* SPN against a slash-bearing cache.
        # The no-slash branch does server.split('/')[1] on the SEARCH string;
        # if the search string has no '/', that indexes out of range.
        c = ccache.CCache()
        c.credentials.append(make_cred('cifs/fs.lab.local@LAB.LOCAL'))
        return c, 'fs.lab.local@LAB.LOCAL', \
            'EC-R no-slash search SPN', ('none',)

    raise ValueError('unknown case %r' % case_id)


CASES = [
    'EC01-direct', 'EC01-poison', 'EC01-target-poison',
    'EC01-empty-third', 'EC01-fourpart',
    'EC02-referral', 'EC02-referral-anyspn',
    'EC03-machine', 'EC03-user',
    'EC05-2part-port', 'EC05-3part-port',
    'ECR-noslash-search',
]


def run_case_in_process(case_id):
    """Runs one case and returns a result dict. Called inside the child."""
    try:
        cache, search, desc, expect = build_case(case_id)
    except Exception as e:
        return {'case': case_id, 'outcome': 'fixture-error',
                'detail': '%s: %s' % (type(e).__name__, e)}

    try:
        result = cache.getCredential(search)
    except Exception as e:
        return {'case': case_id, 'desc': desc, 'search': search,
                'outcome': 'crash',
                'detail': '%s: %s' % (type(e).__name__, e)}

    # Classify against expectation.
    got_idx = None
    for i, c in enumerate(cache.credentials):
        if c is result:
            got_idx = i
            break

    if expect[0] == 'none':
        if result is None:
            outcome = 'correct'
            detail = 'returned None as expected'
        else:
            outcome = 'silent-wrong-result'
            detail = 'expected None, got credential idx %s (%s)' % (
                got_idx, cache.credentials[got_idx]['server'].prettyPrint().decode('utf-8', 'replace'))
    else:  # ('match', idx)
        want = expect[1]
        if result is None:
            outcome = 'miss'
            detail = 'expected match idx %s, got None' % want
        elif got_idx == want:
            outcome = 'correct'
            detail = 'matched expected idx %s' % want
        else:
            outcome = 'silent-wrong-result'
            detail = 'expected idx %s, got idx %s' % (want, got_idx)

    return {'case': case_id, 'desc': desc, 'search': search,
            'outcome': outcome, 'detail': detail}


def run_child(case_id):
    print(json.dumps(run_case_in_process(case_id)))


def run_version(label, path, case_id):
    """Spawn a child with PYTHONPATH=path, run one case, return its dict."""
    env = dict(os.environ)
    env['PYTHONPATH'] = path
    # Run from a neutral cwd so the local package never shadows the target.
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), '--child', case_id],
        capture_output=True, text=True, env=env, cwd='/tmp')
    if proc.returncode != 0 or not proc.stdout.strip():
        return {'case': case_id, 'outcome': 'harness-error',
                'detail': (proc.stderr or proc.stdout).strip()[-400:]}
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as e:
        return {'case': case_id, 'outcome': 'harness-error',
                'detail': 'bad child output: %s / %r' % (e, proc.stdout[-300:])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline', default='/tmp/impacket-prefix',
                    help='PYTHONPATH root for the pre-fix tree')
    ap.add_argument('--patched', default='/home/user/impacket',
                    help='PYTHONPATH root for the patched tree')
    ap.add_argument('--child', help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.child:
        run_child(args.child)
        return

    # Confirm module isolation up front.
    for label, path in (('baseline', args.baseline), ('patched', args.patched)):
        env = dict(os.environ); env['PYTHONPATH'] = path
        p = subprocess.run(
            [sys.executable, '-c',
             'import impacket.krb5.ccache as m; print(m.__file__)'],
            capture_output=True, text=True, env=env, cwd='/tmp')
        print('# %-9s ccache: %s' % (label, p.stdout.strip() or p.stderr.strip()))
    print()

    hdr = '%-22s | %-22s | %-22s | %s' % ('CASE', 'BASELINE', 'PATCHED', 'DELTA')
    print(hdr)
    print('-' * len(hdr))
    for case_id in CASES:
        b = run_version('baseline', args.baseline, case_id)
        p = run_version('patched', args.patched, case_id)
        bo, po = b.get('outcome'), p.get('outcome')
        delta = 'same' if bo == po else 'CHANGED'
        print('%-22s | %-22s | %-22s | %s' % (case_id, bo, po, delta))
        # Emit detail lines for anything not a clean 'correct/correct'.
        if bo != 'correct':
            print('    baseline: %s' % b.get('detail', ''))
        if po != 'correct':
            print('    patched : %s' % p.get('detail', ''))


if __name__ == '__main__':
    main()
