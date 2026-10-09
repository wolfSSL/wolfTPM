#!/usr/bin/env python3
"""Build the wolfTPM manual with wolfSSL/documentation's shared tooling."""

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml
from markdown.extensions.toc import slugify


MANUAL = "wolfTPM"
PDF = {"en": "wolfTPM-Manual.pdf", "ja": "wolfTPM-Manual-jp.pdf"}
CONFIG = {"en": "mkdocs.yml", "ja": "mkdocs-ja.yml"}
DOCS = {"en": "docs", "ja": "docs/ja"}
HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
LINK = re.compile(r"\]\((?:([^)#]+\.md))?(?:#([^)]+))?\)")
EXCLUDE_DIRS = {"dev", "assets", "ja"}
# Legacy longform docs kept for Doxygen and the top-level README; not manual pages.
EXCLUDE_FILES = {"README.md", "FWTPM.md", "SWTPM.md", "DEVTPM.md", "WindowTBS.md"}
GENERATED = re.compile(r"^(group__.+|.+_8h)\.md$")


def pages_from_nav(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from pages_from_nav(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from pages_from_nav(item)


def page_key(page):
    return "wtpm-" + slugify(Path(page).with_suffix("").as_posix().replace("/", "-"), "-")


def heading_slug(title):
    title = re.sub(r"[`*]", "", title)
    title = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", title)
    return slugify(title, "-")


def on_disk_pages(source_docs):
    pages = set()
    for path in source_docs.rglob("*.md"):
        rel = path.relative_to(source_docs)
        if EXCLUDE_DIRS.intersection(rel.parts):
            continue
        if rel.as_posix() in EXCLUDE_FILES:
            continue
        pages.add(rel.as_posix())
    return pages


def stage(documentation_root, source_root, lang):
    manual = documentation_root / MANUAL
    source_docs = source_root / DOCS[lang]
    shared = documentation_root / "common" / "common.am"
    if not source_docs.is_dir() or not shared.is_file():
        raise RuntimeError(f"{source_docs} or documentation/common/common.am is missing")

    config = yaml.safe_load((source_root / CONFIG[lang]).read_text())
    pages = list(pages_from_nav(config["nav"]))
    if not pages or pages[0] != "index.md" or len(set(pages)) != len(pages):
        raise RuntimeError("manual navigation must start at index.md and contain unique pages")

    disk = on_disk_pages(source_docs)
    generated = [p for p in pages if not (source_docs / p).is_file()]
    for page in generated:
        if not GENERATED.match(Path(page).name):
            raise RuntimeError(f"navigation references a missing page: {page}")
    hand = [p for p in pages if p not in generated]
    if set(hand) != disk:
        raise RuntimeError(
            f"manual navigation mismatch: missing={sorted(disk - set(hand))}, "
            f"unknown={sorted(set(hand) - disk)}"
        )

    manual.mkdir(exist_ok=True)
    for name in ("src", "build", "html", "api"):
        path = manual / name
        if path.exists():
            shutil.rmtree(path)
    keep_suffixes = (".md", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css")

    def ignore(directory, names):
        ignored = set(shutil.ignore_patterns(*EXCLUDE_DIRS, *EXCLUDE_FILES)(
            directory, names))
        for name in names:
            full = os.path.join(directory, name)
            if os.path.isdir(full):
                continue
            if not name.lower().endswith(keep_suffixes):
                ignored.add(name)
        return ignored

    shutil.copytree(source_docs, manual / "src", ignore=ignore)
    shutil.copyfile(manual / "src" / "index.md", manual / "src" / "Home.md")
    (manual / "build").mkdir()
    ordered = ["Home.md" if page == "index.md" else page for page in pages]
    (manual / "build" / "order.mk").write_text(
        "SOURCES := " + " ".join(ordered) + "\nAPPENDIX :=\n"
    )
    (manual / "build" / "order.json").write_text(json.dumps(pages) + "\n")
    (manual / "build" / "generated.json").write_text(json.dumps(generated) + "\n")
    shutil.copyfile(source_root / "tools" / "docs-manual" / "Makefile",
                    manual / "manual.generated.mk")

    config["docs_dir"] = "build/html"
    config["site_dir"] = "html"
    config["theme"] = {
        "name": None,
        "custom_dir": "../mkdocs-material/material",
        "language": lang,
        "palette": {"primary": "indigo", "accent": "indigo"},
        "font": {"text": "Roboto", "code": "Roboto Mono"},
        "icon": "logo.png",
        "logo": "logo.png",
        "favicon": "logo.png",
        "feature": {"tabs": True},
    }
    config["extra_css"] = ["skin.css", "table-code.css"]
    config["markdown_extensions"] = ["tables", "fenced_code", "admonition",
                                     {"toc": {"permalink": True}}]
    config["plugins"] = ["search"]
    config["use_directory_urls"] = False
    (manual / "mkdocs.yml").write_text(yaml.safe_dump(config, sort_keys=False))

    header = (documentation_root / "wolfBoot" / "header.txt").read_text()
    header = header.replace("wolfBoot Documentation", "wolfTPM Manual")
    header = re.sub(r"(\\copyright\s+)\d{4}", r"\g<1>2026", header)
    # Widen the PDF table-of-contents number boxes so deep multi-digit numbers
    # (e.g. 19.3.13) stay clear of the entry titles instead of overlapping them.
    toc_fix = (
        "    - \\usepackage{tocloft}\n"
        "    - \\setlength{\\cftsecnumwidth}{3.0em}\n"
        "    - \\setlength{\\cftsubsecnumwidth}{3.8em}\n"
        "    - \\setlength{\\cftsubsubsecnumwidth}{4.8em}\n"
        "subparagraph: yes"
    )
    header = header.replace("subparagraph: yes", toc_fix)
    (manual / "header.txt").write_text(header)
    return manual


def resolve(page, md):
    return os.path.normpath(os.path.join(os.path.dirname(page), md)).replace(os.sep, "/")


def prepare_pdf(documentation_root):
    manual = documentation_root / MANUAL
    pdf_dir = manual / "build" / "pdf"
    pages = json.loads((manual / "build" / "order.json").read_text())
    generated = set(json.loads((manual / "build" / "generated.json").read_text()))
    hand = [p for p in pages if p not in generated]

    headers = {}
    for page in hand:
        staged = pdf_dir / ("Home.md" if page == "index.md" else page)
        found = set()
        in_fence = False
        for line in staged.read_text().splitlines():
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
            if not in_fence:
                match = HEADING.match(line)
                if match:
                    found.add(heading_slug(match.group(2)))
        headers[page] = found

    for page in hand:
        staged = pdf_dir / ("Home.md" if page == "index.md" else page)
        output = [f"[]{{#{page_key(page)}}}\n\n"]
        in_fence = False
        seen = set()
        for line in staged.read_text().splitlines(keepends=True):
            anchor = ""
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
            if not in_fence:
                match = HEADING.match(line.rstrip("\n"))
                if match:
                    slug = heading_slug(match.group(2))
                    unique = slug
                    counter = 1
                    while unique in seen:
                        counter += 1
                        unique = f"{slug}-{counter}"
                    seen.add(unique)
                    anchor = f"[]{{#{page_key(page)}-{unique}}}\n\n"

                def rewrite(link):
                    md = link.group(1)
                    fragment = link.group(2)
                    if md is None and fragment is None:
                        return link.group(0)
                    target = page if md is None else resolve(page, md)
                    if target not in headers:
                        return link.group(0)
                    if fragment and fragment not in headers[target]:
                        raise RuntimeError(f"unresolved PDF link: {page} -> {target}#{fragment}")
                    dest = page_key(target) + (f"-{fragment}" if fragment else "")
                    return f"](#{dest})"

                line = LINK.sub(rewrite, line)
            output.append(anchor + line)
        staged.write_text("".join(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "pdf-links"))
    parser.add_argument("--documentation-root", required=True, type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--lang", choices=("en", "ja"), default="en")
    parser.add_argument("--target", choices=("all", "html", "pdf"), default="all")
    args = parser.parse_args()
    documentation_root = args.documentation_root.resolve()
    if args.command == "pdf-links":
        prepare_pdf(documentation_root)
        return
    if args.source_root is None:
        parser.error("build requires --source-root")
    source_root = args.source_root.resolve()
    manual = stage(documentation_root, source_root, args.lang)
    make_args = ["make", "-C", str(manual), "-f", "manual.generated.mk", args.target,
                 f"WT_SOURCE={source_root}", f"PDF={PDF[args.lang]}"]
    if args.lang == "ja":
        make_args.append("DOC_LANG=JA")
    subprocess.run(make_args, check=True)


if __name__ == "__main__":
    main()
