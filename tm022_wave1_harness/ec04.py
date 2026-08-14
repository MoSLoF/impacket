#!/usr/bin/env python3
"""
TM-022 Wave 1 — EC-04: UTF-8 / non-ASCII principal & realm layer analysis.

SPEC BASIS
----------
RFC 4120 §5.2.1 types PrincipalName/Realm as KerberosString (IA5String /
ASCII).  MS-KILE relaxes this: real Windows deployments carry UTF-8 in
principal and realm names (accented hostnames, non-Latin realms).  So a
spec-strict IA5String reading rejects bytes that a real KDC emits.

WHAT THE IMPLEMENTATION ASSUMES
-------------------------------
impacket normalises Python `str` -> `bytes` with six.b(), which on Py3 is
`s.encode("latin-1")`.  Latin-1 covers U+0000..U+00FF only.  Anything above
that (Cyrillic, CJK, emoji, …) raises UnicodeEncodeError.  So the toolchain
silently assumes every principal fits in Latin-1 — narrower than UTF-8, and
narrower than what MS-KILE puts on the wire.

GOAL
----
Probe each layer independently and report WHERE the first failure originates
for each fixture, on both the baseline and patched trees.  The #2242 fix and
#2243 ("Modernize byte string normalization") do not touch this path, so both
versions are expected identical — this probe verifies that expectation and
localises the failure.

USAGE
    python3 ec04.py --baseline /tmp/impacket-prefix --patched /home/user/impacket
"""
import argparse
import json
import os
import subprocess
import sys

# Fixtures: (label, spn_string)
FIXTURES = [
    ('latin1-accent', 'cifs/café.lab.local@LAB.LOCAL'),   # é  -> in Latin-1
    ('cyrillic',      'cifs/СЕРВЕР@ДОМЕН.LOCAL'),  # СЕРВЕР@ДОМЕН.LOCAL
]

# Layers, each a callable name probed in isolation inside the child.
LAYERS = ['six.b', 'types.Principal', 'fromPrincipal', 'prettyPrint', 'getCredential']


def probe(spn):
    """Run each layer for one fixture; return {layer: 'ok' | 'ExcType: msg'}."""
    import six
    from impacket.krb5 import ccache, types, constants
    out = {}

    # Layer 1: six.b() directly on the search string (as getCredential's first
    # line does: b(server.upper())).
    try:
        six.b(spn.upper())
        out['six.b'] = 'ok'
    except Exception as e:
        out['six.b'] = '%s: %s' % (type(e).__name__, e)

    # Layer 2: types.Principal construction (pure string splitting, no encode).
    principal_obj = None
    try:
        principal_obj = types.Principal(
            spn, type=int(constants.PrincipalNameType.NT_SRV_INST.value))
        out['types.Principal'] = 'ok'
    except Exception as e:
        out['types.Principal'] = '%s: %s' % (type(e).__name__, e)

    # Layer 3: fromPrincipal (stores components as-is into CountedOctetString).
    princ = None
    try:
        princ = ccache.Principal()
        princ.fromPrincipal(principal_obj)
        out['fromPrincipal'] = 'ok'
    except Exception as e:
        out['fromPrincipal'] = '%s: %s' % (type(e).__name__, e)

    # Layer 4: prettyPrint (this is where b(component['data']) runs when the
    # stored data is a str -> Latin-1 encode -> UnicodeEncodeError for Cyrillic).
    try:
        princ.prettyPrint()
        out['prettyPrint'] = 'ok'
    except Exception as e:
        out['prettyPrint'] = '%s: %s' % (type(e).__name__, e)

    # Layer 5: full getCredential path with the fixture both cached and searched.
    try:
        c = ccache.CCache()
        cred = ccache.Credential()
        cred['server'] = princ
        c.credentials.append(cred)
        c.getCredential(spn)
        out['getCredential'] = 'ok'
    except Exception as e:
        out['getCredential'] = '%s: %s' % (type(e).__name__, e)

    return out


def run_child():
    results = {label: probe(spn) for label, spn in FIXTURES}
    print(json.dumps(results))


def run_version(path):
    env = dict(os.environ); env['PYTHONPATH'] = path
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), '--child'],
        capture_output=True, text=True, env=env, cwd='/tmp')
    if proc.returncode != 0 or not proc.stdout.strip():
        return {'_error': (proc.stderr or proc.stdout).strip()[-400:]}
    return json.loads(proc.stdout.strip().splitlines()[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline', default='/tmp/impacket-prefix')
    ap.add_argument('--patched', default='/home/user/impacket')
    ap.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.child:
        run_child()
        return

    b = run_version(args.baseline)
    p = run_version(args.patched)

    for label, spn in FIXTURES:
        print('\n### Fixture %s: %s' % (label, spn))
        print('%-16s | %-45s | %-45s' % ('LAYER', 'BASELINE', 'PATCHED'))
        print('-' * 112)
        for layer in LAYERS:
            bv = b.get(label, {}).get(layer, '?')
            pv = p.get(label, {}).get(layer, '?')
            flag = '' if bv == pv else '   <-- DIVERGES'
            print('%-16s | %-45s | %-45s%s' % (layer, bv[:45], pv[:45], flag))


if __name__ == '__main__':
    main()
