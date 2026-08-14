#!/usr/bin/env python3
"""
TM-022 Wave 1 — EC-06: credential selection under mixed expiry / ticket flags
=============================================================================

Spec basis: RFC 4120 §5.3 (``endtime``, ``renew-till``) and §2 (TicketFlags,
including the ``forwardable`` bit). A credential cache legitimately holds more
than one credential for the same service principal — for example an expired
ticket left in place next to a freshly acquired one, or a non-forwardable
ticket alongside a forwardable one obtained for delegation.

Question: when two credentials share a server SPN, which one does
``CCache.getCredential()`` return, and does it consult ``endtime`` or the
ticket flags at all?

Fixture: a cache with two credentials for the SAME SPN
    index 0 : endtime in the PAST,   forwardable bit CLEAR
    index 1 : endtime in the FUTURE, forwardable bit SET

This is a BEHAVIOURAL characterisation, not a severity claim. Whether
getCredential() or its callers own expiry/flag filtering is a contract
question flagged for review — see the report. Timestamps are passed in as
fixed constants (no wall-clock reads) so the fixture is deterministic and
regenerable.

Usage:
    PYTHONPATH=/path/to/impl python3 ec06.py
"""

# Fixed reference instants (deterministic; no time.time() reads).
PAST_ENDTIME   = 1_000_000_000   # 2001-09-09 — long expired
FUTURE_ENDTIME = 4_000_000_000   # 2096-10-02 — far future

# TicketFlags bit for 'forwardable' is bit 1 (RFC 4120 §5.3, MSB-0 numbering);
# in the 32-bit little-endian-of-bit-string form impacket stores, the concrete
# integer value is not what matters here — we set two clearly distinct values.
FLAGS_NON_FWD = 0x00000000
FLAGS_FWD     = 0x40000000       # 'forwardable' set


def make_cred(ccache, types, constants, spn, endtime, flags):
    cred = ccache.Credential()
    principal = ccache.Principal()
    p = types.Principal(
        spn, type=int(constants.PrincipalNameType.NT_SRV_INST.value))
    principal.fromPrincipal(p)
    cred["server"] = principal
    # Populate the Times sub-structure and ticket flags.
    times = ccache.Times()
    times["authtime"] = endtime
    times["starttime"] = endtime
    times["endtime"] = endtime
    times["renew_till"] = endtime
    cred["time"] = times
    cred["tktflags"] = flags
    return cred


def main():
    from impacket.krb5 import ccache, types, constants

    SPN = "cifs/fs.lab.local@LAB.LOCAL"
    cc = ccache.CCache()
    # index 0: expired + non-forwardable
    cc.credentials.append(
        make_cred(ccache, types, constants, SPN, PAST_ENDTIME, FLAGS_NON_FWD))
    # index 1: valid + forwardable
    cc.credentials.append(
        make_cred(ccache, types, constants, SPN, FUTURE_ENDTIME, FLAGS_FWD))

    got = cc.getCredential(SPN, anySPN=True)
    idx = None
    for i, c in enumerate(cc.credentials):
        if c is got:
            idx = i
            break

    endtime = got["time"]["endtime"] if got is not None else None
    flags = got["tktflags"] if got is not None else None

    print("EC-06 credential selection under mixed expiry/flags")
    print("-" * 60)
    print(f"cache index 0 : endtime={PAST_ENDTIME} (EXPIRED), "
          f"tktflags=0x{FLAGS_NON_FWD:08x} (non-forwardable)")
    print(f"cache index 1 : endtime={FUTURE_ENDTIME} (VALID),  "
          f"tktflags=0x{FLAGS_FWD:08x} (forwardable)")
    print("-" * 60)
    print(f"getCredential returned index : {idx}")
    print(f"  returned endtime  : {endtime} "
          f"({'EXPIRED' if endtime == PAST_ENDTIME else 'valid'})")
    print(f"  returned tktflags : 0x{flags:08x}" if flags is not None else
          "  returned tktflags : None")
    print("-" * 60)
    if idx == 0:
        print("RESULT: first-match selection confirmed. getCredential returns")
        print("the FIRST credential whose server SPN matches, with NO endtime")
        print("or ticket-flag filtering. An expired / non-forwardable ticket")
        print("sitting ahead of a valid one is returned in preference.")
    else:
        print("RESULT: a non-first credential was returned — investigate the")
        print("selection logic; this contradicts the first-match reading.")
    print("Contract question (flagged, not scored): should getCredential own")
    print("expiry/flag filtering, or is that the caller's responsibility?")


if __name__ == "__main__":
    main()
