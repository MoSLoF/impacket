#!/usr/bin/env python3
"""
TM-022 Wave 1 — impacket krb5 ccache differential harness
==========================================================

Purpose
-------
Differential test harness for ``CCache.getCredential()`` covering the anySPN
fallback path. It constructs synthetic in-memory credential caches (no live AD,
no disk artifacts) and exercises spec-legal Kerberos service-principal shapes
that a flat single-domain test lab never produces:

  EC-01  3-part SPN            service/host/domain@REALM   (e.g. Rubeus dump)
  EC-02  cross-realm ref TGT   krbtgt/CHILD.REALM@PARENT.REALM
  EC-03  S4U2Self ST           no-service-type principal (machine vs user)
  EC-05  port specifier        HTTP/host:8443@REALM and 3-part+port
  EC-R   no-slash search SPN   search term without '/' vs slash-bearing cache

Each case is run against two impacket checkouts and the outcomes compared:

  baseline : commit 2dae5c7f (parent of the fix — pre-fix behaviour)
  patched  : commit 243d64a6 ("Fix IndexError ... 3-part SPNs", PR #2242)

Spec basis: RFC 4120 §6.2 (principal names), MS-KILE §2.2 / SPN grammar,
MS-SFU §3.2.5.1.2 (S4U2Self), RFC 4120 §3.3.3 (cross-realm referral).

Usage
-----
  # Orchestrate both versions and print a comparison table:
  python3 harness.py --baseline /path/to/baseline --patched /path/to/patched

  # Single-version worker (prints JSON for the impacket on PYTHONPATH):
  PYTHONPATH=/path/to/impl python3 harness.py --worker LABEL

The harness never imports impacket in orchestrator mode; each version is loaded
in its own subprocess so the two module trees never collide in one interpreter.
"""
import argparse
import json
import os
import subprocess
import sys
import traceback


# --------------------------------------------------------------------------
# Case definitions — version-independent. `cache` and `search` are SPN strings.
# `expect` is the spec-correct result: an SPN string that SHOULD be returned,
# or None meaning "no match exists, should return None gracefully (not crash)".
# --------------------------------------------------------------------------
CASES = [
    # ---- EC-01: 3-part SPN in the cache -----------------------------------
    dict(
        id="EC-01a", name="3-part SPN direct lookup (anySPN fallback)",
        cache=[
            "LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL",
            "cifs/fs.lab.local@LAB.LOCAL",
        ],
        # port forces a miss in the exact-match loop -> enters anySPN loop,
        # whose first iteration hits the 3-part cached cred.
        search="LDAP/us-dc.us.techcorp.local:389@US.TECHCORP.LOCAL",
        expect="LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL",
        note="3-part cached SPN must be matchable on host+realm.",
    ),
    dict(
        id="EC-01b", name="Poisoning: unrelated lookup crashes on a 3-part cred",
        cache=[
            "LDAP/us-dc.us.techcorp.local/us.techcorp.local@US.TECHCORP.LOCAL",
            "cifs/fs.lab.local@LAB.LOCAL",
        ],
        # A krbtgt lookup that is NOT in cache -> exact loop misses -> anySPN
        # loop iterates and touches the 3-part cred at index 0. This is the
        # call shape tools issue unconditionally, so one dumped 3-part ticket
        # anywhere in the cache poisons every subsequent lookup on baseline.
        search="krbtgt/US.TECHCORP.LOCAL@US.TECHCORP.LOCAL",
        expect=None,  # not present: correct behaviour is a graceful None
        note="One 3-part cred must not crash lookups for other SPNs.",
    ),
    # ---- EC-02: cross-realm referral TGT ----------------------------------
    dict(
        id="EC-02", name="Cross-realm referral TGT (2-part, 2nd comp is realm)",
        cache=["krbtgt/CHILD.REALM@PARENT.REALM"],
        search="krbtgt/child.realm:88@parent.realm",  # port -> anySPN path
        expect="krbtgt/CHILD.REALM@PARENT.REALM",
        note="A 2-part krbtgt whose 2nd component is a realm must match.",
    ),
    # ---- EC-03: S4U2Self ST with no service type --------------------------
    dict(
        id="EC-03a", name="S4U2Self ST — machine account (hostname$@REALM)",
        cache=["US-DC$@US.TECHCORP.LOCAL"],
        search="cifs/us-dc.us.techcorp.local@US.TECHCORP.LOCAL",
        expect="US-DC$@US.TECHCORP.LOCAL",
        note="Machine-account ST (no slash) should match its SPN lookup.",
    ),
    dict(
        id="EC-03b", name="S4U2Self ST — user account (no '$')",
        cache=["john.doe@US.TECHCORP.LOCAL"],
        search="cifs/john.doe@US.TECHCORP.LOCAL",
        expect="john.doe@US.TECHCORP.LOCAL",
        note="User-principal ST cannot be represented by the '$'-appending "
             "no-slash branch — expected silent miss (returns None).",
    ),
    # ---- EC-05: port specifiers -------------------------------------------
    dict(
        id="EC-05a", name="2-part SPN with port",
        cache=["HTTP/web.lab.local:8443@LAB.LOCAL"],
        search="HTTP/web.lab.local@LAB.LOCAL",
        expect="HTTP/web.lab.local:8443@LAB.LOCAL",
        note="Port in the 2nd component must be stripped for comparison.",
    ),
    dict(
        id="EC-05b", name="3-part SPN with port in host component",
        cache=["LDAP/dc.lab.local:3268/lab.local@LAB.LOCAL"],
        search="LDAP/dc.lab.local@LAB.LOCAL",
        expect="LDAP/dc.lab.local:3268/lab.local@LAB.LOCAL",
        note="Port + 3-part combination — the hardest shape for the 3-part "
             "branch. Baseline IndexErrors before the port is even considered.",
    ),
    # ---- EC-R: no-slash search SPN vs slash-bearing cache -----------------
    dict(
        id="EC-R", name="No-slash search term against a slash-bearing cache",
        cache=["cifs/fs.lab.local@LAB.LOCAL"],
        search="US-DC$@US.TECHCORP.LOCAL",  # no '/'
        expect=None,  # no match exists; correct behaviour is graceful None
        note="Search-side mirror of the EC-01 assumption: the anySPN loop "
             "indexes server.split('/')[1] with no guard that the SEARCH "
             "term contains a slash.",
    ),
]


# --------------------------------------------------------------------------
# Worker: runs in a subprocess with a single impacket on PYTHONPATH.
# --------------------------------------------------------------------------
def build_cache(ccache, types, constants, spns):
    def make_cred(spn_string):
        cred = ccache.Credential()
        principal = ccache.Principal()
        p = types.Principal(
            spn_string,
            type=int(constants.PrincipalNameType.NT_SRV_INST.value),
        )
        principal.fromPrincipal(p)
        cred["server"] = principal
        return cred

    cc = ccache.CCache()
    for spn in spns:
        cc.credentials.append(make_cred(spn))
    return cc


def classify(result_spn, exc, expect):
    """Map a raw (result, exception) pair to a semantic outcome vs `expect`."""
    if exc is not None:
        return "crash"
    if expect is None:
        # Correct behaviour is a graceful None.
        return "correct" if result_spn is None else "silent-wrong-result"
    # A specific match is expected.
    if result_spn is None:
        return "silent-wrong-result"   # a match existed but was missed
    if result_spn.upper() == expect.upper():
        return "correct"
    return "silent-wrong-result"       # returned the wrong credential


def run_worker(label):
    from impacket.krb5 import ccache, types, constants  # noqa: E402

    results = []
    for case in CASES:
        entry = dict(id=case["id"], name=case["name"], search=case["search"],
                     cache=case["cache"], note=case["note"])
        try:
            cc = build_cache(ccache, types, constants, case["cache"])
            got = cc.getCredential(case["search"], anySPN=True)
            result_spn = (got["server"].prettyPrint().decode("utf-8", "replace")
                          if got is not None else None)
            entry["result"] = result_spn
            entry["exc_type"] = None
            entry["exc_msg"] = None
            entry["outcome"] = classify(result_spn, None, case["expect"])
        except Exception as e:  # noqa: BLE001 — we are characterising failures
            entry["result"] = None
            entry["exc_type"] = type(e).__name__
            entry["exc_msg"] = str(e)
            entry["exc_tb"] = traceback.format_exc().splitlines()[-3:]
            entry["outcome"] = classify(None, e, case["expect"])
        results.append(entry)

    print(json.dumps(dict(label=label, results=results)))


# --------------------------------------------------------------------------
# Orchestrator: run the worker under each version and diff.
# --------------------------------------------------------------------------
def run_version(path, label):
    env = dict(os.environ)
    env["PYTHONPATH"] = path + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--worker", label],
        env=env, capture_output=True, text=True,
    )
    if out.returncode != 0 or not out.stdout.strip():
        sys.stderr.write(f"[worker {label} failed]\n{out.stderr}\n")
        sys.exit(2)
    return json.loads(out.stdout.strip().splitlines()[-1])


def fmt_outcome(entry):
    o = entry["outcome"]
    if o == "crash":
        return f"crash ({entry['exc_type']})"
    if o == "correct":
        return "correct"
    return "SILENT-WRONG"


def orchestrate(baseline_path, patched_path):
    base = run_version(baseline_path, "baseline")
    patch = run_version(patched_path, "patched")
    bmap = {e["id"]: e for e in base["results"]}
    pmap = {e["id"]: e for e in patch["results"]}

    print("=" * 78)
    print("TM-022 Wave 1 — CCache.getCredential differential")
    print(f"  baseline: 2dae5c7f (pre-fix)   patched: 243d64a6 (PR #2242)")
    print("=" * 78)
    hdr = f"{'CASE':<8} {'BASELINE':<22} {'PATCHED':<22} DELTA"
    print(hdr)
    print("-" * 78)
    regressions = 0
    for case in CASES:
        cid = case["id"]
        b, p = bmap[cid], pmap[cid]
        delta = ""
        if b["outcome"] != p["outcome"]:
            if b["outcome"] == "crash" and p["outcome"] == "correct":
                delta = "FIXED"
            elif b["outcome"] == "correct" and p["outcome"] != "correct":
                delta = "REGRESSION"; regressions += 1
            else:
                delta = f"{b['outcome']}->{p['outcome']}"
        else:
            delta = "(same)"
        print(f"{cid:<8} {fmt_outcome(b):<22} {fmt_outcome(p):<22} {delta}")
    print("-" * 78)
    print(f"regressions introduced by patch: {regressions}")
    # Full detail as JSON for the report.
    detail = {"baseline": base, "patched": patch}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "harness_results.json"), "w") as fh:
        json.dump(detail, fh, indent=2)
    print("wrote harness_results.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", metavar="LABEL",
                    help="internal: run cases for the impacket on PYTHONPATH")
    ap.add_argument("--baseline", help="path to baseline impacket checkout")
    ap.add_argument("--patched", help="path to patched impacket checkout")
    args = ap.parse_args()

    if args.worker:
        run_worker(args.worker)
    elif args.baseline and args.patched:
        orchestrate(args.baseline, args.patched)
    else:
        ap.error("provide --worker LABEL, or both --baseline and --patched")


if __name__ == "__main__":
    main()
