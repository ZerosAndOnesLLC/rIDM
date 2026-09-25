#!/usr/bin/env python3
"""Search-engine metadata for the documentation pages mdBook renders.

mdBook gives every page the book's one description and no canonical URL or
social tags. For each page under _site/docs this sets a description taken
from the page's first paragraph, a canonical URL (the introduction's is
docs/, which serves the same page), Open Graph and Twitter tags, and marks
the pages that must not be indexed: the print-everything page, the
table-of-contents frame and the 404 page.
"""

import html
import re
import sys
from pathlib import Path

BASE = "https://zerosandonesllc.github.io/rIDM/"
OG_IMAGE = BASE + "assets/og.png"
NOINDEX = {"print.html", "toc.html", "404.html"}
MAX_DESCRIPTION = 155
# Pages whose body is not prose: the admin API reference renders the OpenAPI
# document in the browser.
DESCRIPTIONS = {
    "reference/admin-api/index.html": "The rIDM admin API reference, rendered from its "
    "OpenAPI document: every endpoint, parameter, schema and permission.",
}

DESCRIPTION = re.compile(r'<meta name="description" content="([^"]*)">')
TITLE = re.compile(r"<title>(.*?)</title>", re.S)
MAIN = re.compile(r"<main>(.*?)</main>", re.S)
BLOCK = re.compile(r"<(p|li)>(.*?)</\1>", re.S)
TAG = re.compile(r"<[^>]+>")


def description(page: str, fallback: str) -> str:
    """The page's opening prose, paragraphs and list items in order, until
    there is enough for a search result."""
    main = MAIN.search(page)
    text = ""
    for block in BLOCK.finditer(main.group(1) if main else ""):
        if text.endswith(":"):
            # A lead-in to a table or list that is not quoted: end the sentence.
            text = text[:-1] + "."
        text += " " + " ".join(html.unescape(TAG.sub("", block.group(2))).split())
        if len(text) >= MAX_DESCRIPTION - 30:
            break
    text = text.strip()
    if len(text) > MAX_DESCRIPTION:
        text = text[: MAX_DESCRIPTION - 1].rsplit(" ", 1)[0].rstrip(",;:") + "…"
    return text.rstrip(":") or fallback


def canonical(rel: str) -> str:
    if rel in ("index.html", "introduction.html"):
        return BASE + "docs/"
    if rel.endswith("/index.html"):
        return BASE + "docs/" + rel[: -len("index.html")]
    return BASE + "docs/" + rel


def process(path: Path, rel: str) -> None:
    page = path.read_text(encoding="utf-8")
    if 'rel="canonical"' in page:
        return
    if rel in NOINDEX:
        if 'name="robots"' in page:
            return
        tags = '<meta name="robots" content="noindex">'
    else:
        fallback = DESCRIPTION.search(page)
        fallback = html.unescape(fallback.group(1)) if fallback else ""
        desc = DESCRIPTIONS.get(rel) or description(page, fallback)
        desc = html.escape(desc, quote=True)
        meta = f'<meta name="description" content="{desc}">'
        if DESCRIPTION.search(page):
            page = DESCRIPTION.sub(lambda _: meta, page, 1)
        else:
            page = page.replace("</head>", f"    {meta}\n    </head>", 1)
        title = TITLE.search(page)
        title = title.group(1).strip() if title else "rIDM"
        url = canonical(rel)
        tags = "\n        ".join(
            [
                f'<link rel="canonical" href="{url}">',
                '<meta property="og:type" content="article">',
                '<meta property="og:site_name" content="rIDM">',
                f'<meta property="og:title" content="{title}">',
                f'<meta property="og:description" content="{desc}">',
                f'<meta property="og:url" content="{url}">',
                f'<meta property="og:image" content="{OG_IMAGE}">',
                '<meta name="twitter:card" content="summary_large_image">',
            ]
        )
    page = page.replace("</head>", f"    {tags}\n    </head>", 1)
    path.write_text(page, encoding="utf-8")


def main(root: str) -> None:
    docs = Path(root)
    for path in sorted(docs.rglob("*.html")):
        process(path, path.relative_to(docs).as_posix())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "_site/docs")
