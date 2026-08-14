# TM-022 Wave 1 — impacket ccache differential harness

Fixture-driven, spec-first edge-case tests for `CCache.getCredential()` SPN
matching, run differentially against a pre-fix baseline and the patched tree.
Findings write-up: [`../reports/S2_impacket_findings.md`](../reports/S2_impacket_findings.md).

## Layout
| File | Covers |
|------|--------|
| `harness.py` | EC-01, EC-02, EC-03, EC-05, EC-R — crash / correctness cases in the anySPN fallback loop |
| `ec04.py` | EC-04 — UTF-8 / non-ASCII per-layer failure localisation (`six.b` … `getCredential`) |
| `ec06.py` | EC-06 — expiry / ticket-flag ordering in the selection layer |

## Versions
- **baseline** `2dae5c7` — parent of the #2242 fix (`243d64a^`), 0.13.1-era, pre-fix.
- **patched** `4c09897` — branch HEAD, contains the #2242 3-part-SPN fix.

## Setup
```bash
# baseline worktree (pre-fix)
git worktree add /tmp/impacket-prefix 243d64a^
# minimum deps
pip install pyasn1 six pycryptodomex --break-system-packages
```

## Run
Each script spawns one subprocess per version with an explicit `PYTHONPATH`
(two copies of `impacket.krb5.ccache` cannot coexist in one interpreter) and
diffs the outcomes. Defaults: `--baseline /tmp/impacket-prefix`,
`--patched /home/user/impacket`.
```bash
python3 harness.py     # EC-01/02/03/05 + EC-R differential table
python3 ec04.py        # EC-04 per-layer UTF-8 table
python3 ec06.py        # EC-06 ordering verdict
# override paths:
python3 harness.py --baseline /tmp/impacket-prefix --patched /path/to/patched
```

All fixtures are constructed in-memory from
`impacket.krb5.{ccache,types,constants}` — no live AD, no ccache files on disk —
so they are regenerable anywhere the library imports.
