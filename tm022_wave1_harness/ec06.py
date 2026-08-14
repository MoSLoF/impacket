#!/usr/bin/env python3
"""EC-06: does the selection layer inspect endtime/tktflags? Order-dependence test."""
import sys
from impacket.krb5.ccache import CCache, Credential, Principal, Times
from impacket.krb5 import types
from impacket.krb5.constants import PrincipalNameType, TicketFlags

print("module:", sys.modules['impacket.krb5.ccache'].__file__)
NT = PrincipalNameType.NT_SRV_INST.value
SPN = "cifs/fs.lab.local@LAB.LOCAL"

def mkcred(spn, endtime, flags, tag):
    c = Credential()
    c["server"] = Principal(); c["server"].fromPrincipal(types.Principal(spn, type=NT))
    c["client"] = Principal(); c["client"].fromPrincipal(types.Principal("user@LAB.LOCAL", type=PrincipalNameType.NT_PRINCIPAL.value))
    t = Times(); t["authtime"]=0; t["starttime"]=0; t["endtime"]=endtime; t["renew_till"]=0
    c["time"] = t
    c["tktflags"] = flags
    c._tag = tag
    return c

PAST   = 100000              # 1970-ish, long expired
FUTURE = 4102444800          # year 2100
FORWARDABLE = 0x40000000

cc = CCache()
cc.credentials.append(mkcred(SPN, PAST,   0,           "EXPIRED-nonfwd (first)"))
cc.credentials.append(mkcred(SPN, FUTURE, FORWARDABLE, "VALID-forwardable (second)"))

r = cc.getCredential(SPN)
print("Two creds for same SPN: [0]=expired/non-fwd, [1]=valid/forwardable")
print("getCredential picked -> endtime=%d flags=0x%x  => %s" % (
    r["time"]["endtime"], r["tktflags"],
    "EXPIRED ticket selected (no expiry check)" if r["time"]["endtime"]==PAST else "valid selected"))
print("forwardable bit set on selection? ", bool(r["tktflags"] & FORWARDABLE))
print("NOTE: selection is purely first-structural-match; endtime & tktflags ignored.")
