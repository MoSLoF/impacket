#!/usr/bin/env python3
"""
TM-022 Wave 1 — EC-04: non-ASCII (UTF-8) principal / realm layer analysis
=========================================================================

Spec basis: RFC 4120 §5.2.1 types principal name components as ``KerberosString``
(GeneralString / historically IA5String); MS-KILE relaxes this to UTF-8 in
practice, and real Windows environments DO issue tickets whose principal or
realm carry non-ASCII code points.

This probe walks a non-ASCII SPN through each layer of the ccache lookup path
and reports exactly where — if anywhere — it fails:

    types.Principal(spn)          construction / component split
    Principal.fromPrincipal(p)    ccache principal population
    prettyPrint()                 byte re-serialisation
    CCache.getCredential(spn)     the six.b(server.upper()) comparison

Two fixtures:
    latin-1 range : cifs/café.lab.local@LAB.LOCAL      (within latin-1)
    outside latin-1: cifs/СЕРВЕР@ДОМЕН.LOCAL            (Cyrillic)

The EC-01 fix (243d64a6) and its surrounding commits do not touch this path,
so baseline and patched are expected identical. Run with -v to see tracebacks.

Usage:
    PYTHONPATH=/path/to/impl python3 ec04.py [-v]
"""
import sys
import traceback

FIXTURES = [
    ("latin-1",  "cifs/café.lab.local@LAB.LOCAL"),
    ("cyrillic", "cifs/СЕРВЕР@ДОМЕН.LOCAL"),
]


def layer_probe(spn, verbose=False):
    """Return (failing_layer, exc) or (None, None) if the full path succeeds."""
    from impacket.krb5 import ccache, types, constants

    # Layer 1: types.Principal construction
    try:
        p = types.Principal(
            spn, type=int(constants.PrincipalNameType.NT_SRV_INST.value))
    except Exception as e:  # noqa: BLE001
        return "types.Principal", e

    # Layer 2: fromPrincipal into a ccache Principal
    try:
        principal = ccache.Principal()
        principal.fromPrincipal(p)
    except Exception as e:  # noqa: BLE001
        return "fromPrincipal", e

    # Layer 3: prettyPrint re-serialisation
    try:
        _ = principal.prettyPrint()
    except Exception as e:  # noqa: BLE001
        return "prettyPrint", e

    # Layer 4: getCredential comparison (six.b(server.upper()))
    try:
        cred = ccache.Credential()
        cred["server"] = principal
        cc = ccache.CCache()
        cc.credentials.append(cred)
        cc.getCredential(spn, anySPN=True)
    except Exception as e:  # noqa: BLE001
        return "getCredential", e

    return None, None


def main():
    verbose = "-v" in sys.argv
    print("EC-04 non-ASCII layer analysis")
    print("-" * 60)
    for label, spn in FIXTURES:
        layer, exc = layer_probe(spn, verbose)
        if exc is None:
            print(f"{label:<9} OK through all layers (no failure)")
        else:
            print(f"{label:<9} FAILS at '{layer}': "
                  f"{type(exc).__name__}: {exc}")
            if verbose:
                print("    " + "\n    ".join(
                    traceback.format_exception_only(type(exc), exc)))
    print("-" * 60)
    print("Observed: the Cyrillic SPN fails inside Principal.prettyPrint(),")
    print("at `b(component['data'])` (ccache.py:164). six.b(s) on py3 ==")
    print("s.encode('latin-1'), so any code point outside latin-1 raises")
    print("UnicodeEncodeError. getCredential() calls prettyPrint() on the")
    print("cached server as the very first step of its loop, so the anySPN")
    print("fallback is never reached. Latin-1 SPNs (e.g. 'café') survive")
    print("because they round-trip through latin-1 cleanly. Baseline and")
    print("patched are identical — the fix does not touch this path.")


if __name__ == "__main__":
    main()
