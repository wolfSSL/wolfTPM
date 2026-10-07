# Building the wolfTPM manual

This file is for maintainers. It is not part of the published manual (the build
excludes `docs/dev/`).

## Layout

`docs/` is the single source of the manual. The `wolfSSL/documentation` repo
renders it to HTML and PDF for the website; nothing in `documentation/wolfTPM/`
holds manual content any more.

- `docs/*.md` are the English manual pages. Each one is a page in `mkdocs.yml`
  `nav`, and the set of pages in the nav must match the files on disk.
- `docs/fwtpm/` is the self-contained firmware TPM section.
- `docs/ja/` is the Japanese mirror, built from `mkdocs-ja.yml`.
- `docs/assets/` holds the logo and CSS for local `mkdocs serve` previews only.
  The website build takes those from the documentation repo's `common/`.
- `docs/dev/` holds maintainer notes like this one and is kept out of the manual.
- The API reference pages (`group__*.md`, `*_8h.md`) are generated at build time
  by Doxygen and doxybook2 from the headers, so they are listed in the nav but
  do not exist in `docs/`.

Keep the `mkdocs.yml` nav and the `mkdocs-ja.yml` nav in step with the pages.

## Local build

Run from the repo root:

```sh
git clone --recurse-submodules https://github.com/wolfSSL/documentation.git build/documentation
git -C build/documentation checkout "$(cat tools/docs-manual/documentation-rev)"
docker build --pull -t wolftpm-docs:local docker/docs
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --mount "type=bind,source=$PWD,target=/work/wolfTPM" \
    --workdir /work/wolfTPM wolftpm-docs:local \
    python3 tools/docs_manual.py build \
        --documentation-root /work/wolfTPM/build/documentation \
        --source-root /work/wolfTPM --target all
```

Outputs land in `build/documentation/wolfTPM/`: `html/` and `wolfTPM-Manual.pdf`.
Add `--lang ja` for the Japanese manual (`wolfTPM-Manual-jp.pdf`). For a quick
HTML preview without the full toolchain, `mkdocs serve` against `mkdocs.yml`
works once `mkdocs` and `mkdocs-material` are installed; the generated API pages
show as warnings because Doxygen has not run.

## Website

The `wolfSSL/documentation` repo has a `wolfTPM` target that clones this repo at
a pinned ref and runs `tools/docs_manual.py`. The nightly build publishes to
`https://www.wolfssl.com/documentation/manuals/wolftpm/`. The website upload list
lives outside these public repos; if it names manuals explicitly rather than
publishing all build output, it needs a one-time wolfTPM entry.
