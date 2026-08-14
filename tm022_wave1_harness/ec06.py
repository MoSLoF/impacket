#!/usr/bin/env python3
"""
TM-022 Wave 1 — EC-06: expiry / ticket-flag ordering in CCache.getCredential.

SPEC BASIS
----------
RFC 4120 §5.3 (Tickets carry endtime / renew-till) and §2 (TicketFlags:
forwardable, etc.).  A credential cache may legally hold more than one ticket
for the same server principal — e.g. an expired one and a fresh one, or a
non-forwardable one and a forwardable one.

WHAT THE IMPLEMENTATION ASSUMES
-------------------------------
CCache.getCredential selects purely by string-matching the `server` principal.
It never reads `time.endtime` and never reads `tktflags`.  It returns the FIRST
credential whose server matches, in cache-storage order.  So when two
credentials match the same SPN, selection is order-dependent, not
quality-dependent: an expired or non-forwardable ticket stored at a lower index
wins over a valid/forwardable one stored later.

This is a SILENT-WRONG-RESULT (no exception, wrong ticket handed back), which
outranks a crash: the caller proceeds with a dead or unsuitable ticket and the
failure surfaces later and elsewhere (KRB_AP_ERR_TKT_EXPIRED at use time, or a
delegation that silently cannot forward).

The #2242 (3-part SPN) and #2243 (byte normalization) changes do not touch the
selection layer, so baseline and patched are expected identical.

USAGE
    python3 ec06.py --baseline /tmp/impacket-prefix --patched /home/user/impacket
"""
import argparse
import json
import os
import subprocess
import sys

# RFC 4120 TicketFlags are MSB-first in the 32-bit flag word.
# forwardable = bit 1 -> 0x40000000.
FORWARDABLE = 0x40000000


def build_and_probe():
    from impacket.krb5 import ccache, types, constants

    # Track each cred's quality in a side-table keyed by object id, so we never
    # have to read the (deliberately partial) packed header back out -- reading
    # a nested Times field would force impacket to pack the unset 'client'
    # field and raise.  getCredential itself only ever touches c['server'].
    quality = {}

    def make_cred(spn, endtime, tktflags):
        cred = ccache.Credential()
        princ = ccache.Principal()
        princ.fromPrincipal(types.Principal(
            spn, type=int(constants.PrincipalNameType.NT_SRV_INST.value)))
        cred['server'] = princ
        # Populate a Times header so the fixture is a faithful credential.
        t = ccache.Times()
        t['authtime'] = 0
        t['starttime'] = 0
        t['endtime'] = endtime
        t['renew_till'] = endtime
        cred['time'] = t
        cred['tktflags'] = tktflags
        quality[id(cred)] = {'endtime': endtime,
                             'forwardable': bool(tktflags & FORWARDABLE),
                             'expired': endtime < 2000000000}
        return cred

    SPN = 'cifs/fs.lab.local@LAB.LOCAL'
    PAST = 1000000000     # 2001-09-09, long expired
    FUTURE = 4102444800   # 2100-01-01, far future

    results = {}

    def describe(got, creds):
        idx = next((i for i, c in enumerate(creds) if c is got), -1)
        q = quality.get(id(got), {}) if got is not None else {}
        return idx, q

    # Scenario A: index 0 = expired+non-forwardable, index 1 = valid+forwardable.
    c = ccache.CCache()
    c.credentials.append(make_cred(SPN, PAST, 0))               # idx0: bad
    c.credentials.append(make_cred(SPN, FUTURE, FORWARDABLE))   # idx1: good
    idx, q = describe(c.getCredential(SPN), c.credentials)
    results['expired-first'] = {
        'returned_index': idx,
        'returned_endtime': q.get('endtime'),
        'returned_forwardable': q.get('forwardable'),
        'returned_expired': q.get('expired'),
        'verdict': 'silent-wrong-result' if idx == 0 else
                   ('correct' if idx == 1 else 'miss'),
    }

    # Scenario B: reverse the order -> valid first.  Confirms it is pure order,
    # not any latent quality preference.
    c2 = ccache.CCache()
    c2.credentials.append(make_cred(SPN, FUTURE, FORWARDABLE))  # idx0: good
    c2.credentials.append(make_cred(SPN, PAST, 0))              # idx1: bad
    idx2, q2 = describe(c2.getCredential(SPN), c2.credentials)
    results['valid-first'] = {
        'returned_index': idx2,
        'returned_endtime': q2.get('endtime'),
        'returned_forwardable': q2.get('forwardable'),
        'returned_expired': q2.get('expired'),
        'verdict': 'order-dependent (returns idx0 regardless of quality)'
                   if idx2 == 0 else 'unexpected',
    }

    return results


def run_child():
    print(json.dumps(build_and_probe()))


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
    print(json.dumps({'baseline': b, 'patched': p}, indent=2))

    print('\nSummary:')
    for scen in ('expired-first', 'valid-first'):
        bv = b.get(scen, {}).get('verdict', '?')
        pv = p.get(scen, {}).get('verdict', '?')
        same = 'same' if bv == pv else 'CHANGED'
        print('  %-14s baseline=%-55s patched=%-55s [%s]' % (scen, bv, pv, same))


if __name__ == '__main__':
    main()
