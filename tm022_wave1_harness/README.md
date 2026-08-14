# TM-022 Wave 1 — impacket krb5 ccache fixtures

Self-contained, in-memory fixtures for the edge cases in
`TM-022_Wave1_impacket_findings.md`. No live AD, no raw byte crafting.

## Run against two trees (differential)
```bash
# create a pre-fix baseline worktree (parent of fix 243d64a)
git worktree add /tmp/prefix-tree 243d64a^

# IMPORTANT: run from a NEUTRAL cwd, else sys.path[0]=repo-root shadows PYTHONPATH
(cd /tmp && PYTHONPATH=/tmp/prefix-tree      python3 /path/to/harness.py)   # 0.13.1-equiv
(cd /tmp && PYTHONPATH=/path/to/impacket     python3 /path/to/harness.py)   # master
```

- `harness.py` — EC-01, EC-02, EC-03, EC-05 + pathological shapes (EX-a/EX-b residual)
- `ec04.py`    — EC-04 UTF-8 mojibake/crash layer analysis
- `ec06.py`    — EC-06 expiry/flags selection (order-dependence)

Deps: `pyasn1 six pycryptodomex` (`pip install ...`).
