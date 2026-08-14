#!/usr/bin/env python3
"""Render the three assessment .md files to A4 PDFs.

Uses pandoc for Markdown -> HTML and WeasyPrint for HTML -> PDF, both
already installed. Each source .md's YAML front matter is turned into a
cover block; the rest renders with the print CSS in .pdf-style.css.
"""
import re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSS = HERE / ".pdf-style.css"

def parse_front_matter(md: str):
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", md, re.DOTALL)
    if not m:
        return {}, md
    meta = {}
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition(":")
        meta[k.strip()] = v.strip().strip('"')
    return meta, m.group(2)

def front_html(meta):
    if not meta:
        return ""
    kv_order = ["project", "author", "date", "classification"]
    dl = []
    for k in kv_order:
        if k in meta:
            dl.append(f'<dt>{k.title()}</dt><dd>{meta[k]}</dd>')
    return (
        '<div class="front-matter">'
        f'<div class="title">{meta.get("title","")}</div>'
        f'<div class="subtitle">{meta.get("subtitle","")}</div>'
        f'<dl>{"".join(dl)}</dl>'
        '</div>'
    )

def build(src: Path):
    meta, body = parse_front_matter(src.read_text())
    html_body = subprocess.run(
        ["pandoc", "-f", "gfm", "-t", "html5", "--no-highlight"],
        input=body, capture_output=True, text=True, check=True,
    ).stdout
    html = (
        f'<!doctype html><html><head><meta charset="utf-8">'
        f'<title>{meta.get("title","Report")}</title></head>'
        f'<body>{front_html(meta)}{html_body}</body></html>'
    )
    tmp_html = src.with_suffix(".build.html")
    tmp_html.write_text(html)
    out_pdf = src.with_suffix(".pdf")
    # weasyprint CLI
    subprocess.run(
        ["weasyprint", "-s", str(CSS), str(tmp_html), str(out_pdf)],
        check=True,
    )
    tmp_html.unlink()
    print(f"  wrote {out_pdf.name}  ({out_pdf.stat().st_size:,} bytes)")

if __name__ == "__main__":
    for name in ["01_impacket_security_assessment.md",
                 "02_depSNORT_tool_assessment.md",
                 "03_session_transcript.md"]:
        p = HERE / name
        print(f"Building {name} ...")
        build(p)
    print("Done.")
