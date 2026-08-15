# TM-022 Round 4 — Field Notes

Gaps hit during THIS session only. One minor readability gap observed; no gap
affected the correctness of the primary finding.

```
GAP: FN-01 — "root(s)" terminology overload in coverage messaging
OBSERVED: The pinned scan's stderr and JSON both report incompleteness as
  "15 unresolved dependenc(ies) across 15 root(s)" and verdict.coverage carries
  incomplete_roots:15. Meanwhile summary.roots is the single graph root
  [pinned-scan-dir@0.0.0], and the graph genuinely has ONE root. The "15 roots"
  are actually 15 individual packages whose declared build-backend
  (flit_core / maturin / hatchling / setuptools) is unpinned — i.e. each package
  is being treated as the "root" of its own unresolved build-backend subtree.
EXPECTED: For an operator eyeballing output during a graph-topology assessment,
  the word "root" should mean one thing. Seeing "1 root" in the summary and
  "15 root(s)" in the coverage warning of the same scan invites a
  double-take / a false "did resolution explode into 15 trees?" reaction. It did
  not — the graph is a single connected tree; the 15 are build-backend coverage
  anchors.
EFFECT: Cost this session a verification detour (dumped verdict.coverage to
  confirm summary.roots==1 while incomplete_roots==15 were build backends). No
  impact on the primary finding once reconciled, but it briefly muddied the
  central question ("did the graph collapse or fan out?").
SUGGESTED TWEAK: In the coverage/incompleteness message, call these
  "incomplete node(s)" or "resolution anchor(s)" rather than "root(s)", and
  reserve "root" for graph roots. Alternatively, phrase as "15 package(s) with
  unresolved build backends" so the operator isn't parsing "root" in two senses
  within one scan.
```

No other gaps observed. The candidate build-backend "false flag" on
charset-normalizer was investigated and found to be a **correct** detection of an
in-tree PEP 517 backend (`build-backend = "backend"`, `backend-path`), so it is
NOT a field note.
