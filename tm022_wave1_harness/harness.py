#!/usr/bin/env python3
"""TM-022 Wave 1 - impacket krb5 ccache differential harness.
Runs identical fixtures against whichever impacket is on PYTHONPATH.
Reports, per case: outcome = MATCH(<server>) | NONE | EXC:<type>:<msg>.
Fixtures are built entirely in-memory (no live AD, no raw byte crafting):
a ccache Principal is populated from a types.Principal(spn_string)."""
import sys, traceback
from impacket.krb5.ccache import CCache, Credential, Principal
from impacket.krb5 import types
from impacket.krb5.constants import PrincipalNameType

NT = PrincipalNameType.NT_SRV_INST.value

def mkcred(spn, ntype=NT):
    c = Credential()
    c["server"] = Principal()
    c["server"].fromPrincipal(types.Principal(spn, type=ntype))
    return c

def mkcache(spns):
    cc = CCache()
    for s in spns:
        if isinstance(s, tuple):
            cc.credentials.append(mkcred(s[0], s[1]))
        else:
            cc.credentials.append(mkcred(s))
    return cc

def probe(label, cache_spns, search, anyspn=True):
    """Build a cache, search it, report outcome robustly."""
    try:
        cc = mkcache(cache_spns)
    except Exception as e:
        print(f"[{label}] BUILD-EXC {type(e).__name__}: {e}")
        return
    try:
        r = cc.getCredential(search, anyspn)
        if r is None:
            print(f"[{label}] NONE  (search={search!r} anySPN={anyspn})")
        else:
            got = r["server"].prettyPrint().decode("utf-8", "replace")
            print(f"[{label}] MATCH={got!r}  (search={search!r} anySPN={anyspn})")
    except Exception as e:
        print(f"[{label}] EXC {type(e).__name__}: {e}  (search={search!r} anySPN={anyspn})")

def pp(label, spn):
    """Just exercise prettyPrint + getData roundtrip on a principal."""
    try:
        c = mkcred(spn)
        s = c["server"].prettyPrint()
        raw = c["server"].getData()
        re = Principal(raw)
        s2 = re.prettyPrint()
        ok = "ROUNDTRIP-OK" if s == s2 else f"ROUNDTRIP-MISMATCH {s!r} != {s2!r}"
        print(f"[{label}] pretty={s!r} {ok}")
    except Exception as e:
        print(f"[{label}] EXC {type(e).__name__}: {e}")

print("=" * 70)
print("impacket ccache module:", CCache.__module__, "|", sys.modules['impacket.krb5.ccache'].__file__)
print("=" * 70)

TGT = "krbtgt/US.TECHCORP.LOCAL@US.TECHCORP.LOCAL"
THREE = "LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL"

# ---------- EC-01: 3-part SPN poisons subsequent lookups ----------
print("\n--- EC-01: 3-part SPN in anySPN loop ---")
# direct: search for something not present, forcing anySPN loop over 3-part entry
probe("EC01-a direct-3part-search", [THREE], "LDAP/us-dc.us.techcorp.local@US.TECHCORP.LOCAL")
# poisoning: 3-part entry BEFORE a normal TGS that we DO want
probe("EC01-b poison-following-cred",
      [THREE, "cifs/fileserver.us.techcorp.local@US.TECHCORP.LOCAL"],
      "cifs/OTHER.us.techcorp.local@US.TECHCORP.LOCAL")
# the exact-match fast path (first loop) - should this ever be reached?
probe("EC01-c exact-3part", [THREE], THREE)

# ---------- EC-02: cross-realm RTGT krbtgt/child@parent ----------
print("\n--- EC-02: cross-realm referral TGT ---")
RTGT = "krbtgt/CHILD.REALM@PARENT.REALM"
probe("EC02-a rtgt-anyspn-nomatch", [RTGT], "cifs/host.child.realm@CHILD.REALM")
probe("EC02-b rtgt-exact", [RTGT], RTGT)
# realm-only referral with no second slash component variant
probe("EC02-c rtgt-poisons-following",
      [RTGT, "cifs/fs.child.realm@CHILD.REALM"],
      "cifs/nomatch.child.realm@CHILD.REALM")

# ---------- EC-03: S4U2Self ST with no service type (no '/') ----------
print("\n--- EC-03: server principal with no '/' (S4U2Self style) ---")
# a ST from S4U2Self: server principal is the user, e.g. 'Administrator@REALM' (1 component)
probe("EC03-a nosvc-search-with-slash",
      [("Administrator@US.TECHCORP.LOCAL", PrincipalNameType.NT_PRINCIPAL.value)],
      "cifs/administrator.us.techcorp.local@US.TECHCORP.LOCAL")
# machine account host$@REALM
probe("EC03-b host-account",
      [("WS01$@US.TECHCORP.LOCAL", PrincipalNameType.NT_PRINCIPAL.value)],
      "cifs/ws01.us.techcorp.local@US.TECHCORP.LOCAL")
# what if the SEARCH string itself has no '/' while a no-slash cred is present?
probe("EC03-c search-noslash",
      [("WS01$@US.TECHCORP.LOCAL", PrincipalNameType.NT_PRINCIPAL.value)],
      "WS01$@US.TECHCORP.LOCAL")

# ---------- EC-04: non-ASCII principal / realm ----------
print("\n--- EC-04: UTF-8 principal & realm ---")
pp("EC04-a pretty-utf8", "cifs/café-dc.münchen.local@MÜNCHEN.LOCAL")
probe("EC04-b utf8-anyspn",
      ["cifs/café-dc.münchen.local@MÜNCHEN.LOCAL"],
      "cifs/café-dc.münchen.local@MÜNCHEN.LOCAL")
probe("EC04-c utf8-search-mismatch-encoding",
      ["cifs/café-dc.münchen.local@MÜNCHEN.LOCAL"],
      "cifs/other.münchen.local@MÜNCHEN.LOCAL")
pp("EC04-d cyrillic", "host/сервер.домен.local@ДОМЕН.LOCAL")

# ---------- EC-05: port specifiers ----------
print("\n--- EC-05: port in 2-part and 3-part SPN ---")
probe("EC05-a 2part-port-cache",
      ["HTTP/web.lab.local:8443@LAB.LOCAL"],
      "HTTP/web.lab.local@LAB.LOCAL")
probe("EC05-b 2part-port-search",
      ["HTTP/web.lab.local@LAB.LOCAL"],
      "HTTP/web.lab.local:8443@LAB.LOCAL")
probe("EC05-c 3part-port-cache",
      ["LDAP/dc.lab.local:3268/lab.local@LAB.LOCAL"],
      "LDAP/dc.lab.local@LAB.LOCAL")
probe("EC05-d 3part-port-both",
      ["LDAP/dc.lab.local:3268/lab.local@LAB.LOCAL"],
      "LDAP/dc.lab.local:3268/lab.local@LAB.LOCAL")

# ---------- Extra: does 3-part with '@' in third component confuse realm parse? ----------
print("\n--- EXTRA: pathological SPN shapes ---")
# third component itself containing '@' is impossible via ccache (realm is separate),
# but a hostname with embedded ':port' plus 4 parts:
probe("EX-a 4part",
      ["LDAP/dc.lab.local/sub.lab.local/lab.local@LAB.LOCAL"],
      "LDAP/dc.lab.local@LAB.LOCAL")
# search server with NO slash at all, cache has 2-part -> exercises else-branch search side
probe("EX-b search-noslash-vs-2part",
      ["cifs/fs.lab.local@LAB.LOCAL"],
      "fs.lab.local@LAB.LOCAL")
print("\n[DONE]")
