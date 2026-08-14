#!/usr/bin/env python3
"""Pin down EC-04 UTF-8 handling: where does mojibake/crash originate?"""
import sys, traceback
from six import b as six_b
from impacket.krb5.ccache import CCache, Credential, Principal, CountedOctetString
from impacket.krb5 import types
from impacket.krb5.constants import PrincipalNameType

print("module:", sys.modules['impacket.krb5.ccache'].__file__)

# 1) six.b() behaviour on accented vs out-of-latin1
for s in ["café", "МОСКВА"]:
    try:
        print(f"six.b({s!r}) = {six_b(s)!r}")
    except Exception as e:
        print(f"six.b({s!r}) -> {type(e).__name__}: {e}")

# 2) Construct-from-string path (types.Principal -> ccache.Principal), latin-1 range
name = "cifs/café-dc.münchen.local@MÜNCHEN.LOCAL"
c = Credential(); c["server"] = Principal()
c["server"].fromPrincipal(types.Principal(name, type=PrincipalNameType.NT_SRV_INST.value))
pretty = c["server"].prettyPrint()
print("\nconstruct-from-str prettyPrint bytes:", pretty)
print("  is this UTF-8 of 'café'? UTF-8 would contain b'caf\\xc3\\xa9'; got b'caf\\xe9' =>",
      b"caf\xe9" in pretty, "(latin-1 mojibake)")

# 3) Simulate a REAL ccache loaded from disk: components stored as UTF-8 BYTES
raw_name = types.Principal(name, type=PrincipalNameType.NT_SRV_INST.value)
p = Principal()
p.header['name_type'] = raw_name.type
p.header['num_components'] = len(raw_name.components)
realm_os = CountedOctetString()
realm_bytes = raw_name.realm.encode('utf-8')
realm_os['length'] = len(realm_bytes); realm_os['data'] = realm_bytes
p.realm = realm_os
p.components = []
for comp in raw_name.components:
    cb = comp.encode('utf-8')
    os_ = CountedOctetString(); os_['length'] = len(cb); os_['data'] = cb
    p.components.append(os_)
print("\nloaded-as-UTF-8-bytes prettyPrint:", p.prettyPrint())
print("  contains proper UTF-8 b'caf\\xc3\\xa9'? =>", b"caf\xc3\xa9" in p.prettyPrint())

# 4) Where does Cyrillic crash originate? test each layer
cyr = "host/сервер@ДОМЕН.LOCAL"
for stage, fn in [
    ("types.Principal", lambda: types.Principal(cyr)),
    ("fromPrincipal",   lambda: Principal().fromPrincipal(types.Principal(cyr))),
]:
    try:
        fn(); print(f"\n{stage}: OK")
    except Exception as e:
        print(f"\n{stage}: {type(e).__name__}: {e}")
# prettyPrint stage
try:
    cc = Credential(); cc["server"] = Principal()
    cc["server"].fromPrincipal(types.Principal(cyr))
    cc["server"].prettyPrint()
    print("prettyPrint: OK")
except Exception as e:
    print(f"prettyPrint: {type(e).__name__}: {e}")

# 5) getCredential search-string b() crash on cyrillic even with EMPTY-ish cache
cc = CCache()
cc.credentials.append((lambda: (lambda cr: (cr.__setitem__("server", Principal()),
    cr["server"].fromPrincipal(types.Principal("cifs/x@Y")), cr)[-1])(Credential()))())
try:
    cc.getCredential("cifs/сервер@ДОМЕН.LOCAL")
    print("getCredential(cyrillic search): returned without crash")
except Exception as e:
    print(f"getCredential(cyrillic search): {type(e).__name__}: {e}")
