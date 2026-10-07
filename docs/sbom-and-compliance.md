# SBOM and Compliance

wolfTPM can generate a Software Bill of Materials (SBOM) to support compliance with the EU Cyber Resilience Act (CRA). This page covers how to generate it and how the generator is organized.

## SBOM and EU CRA compliance

wolfTPM generates an SBOM in CycloneDX 1.6 and SPDX 2.3 formats. The generator is the wolfGlass snapshot vendored in `tools/sbom/` and pinned by `tools/sbom/.wolfglass-rev`. The SBOM records the configured build options (from `wolftpm/options.h`), hashes the built `libwolftpm` library artifact (shared or static; ELF, Mach-O, or PE), and lists wolfSSL as a dependency so vulnerability scanners can associate wolfSSL advisories with a wolfTPM deployment.

Output is reproducible. Set `SOURCE_DATE_EPOCH` (or build from a git checkout, which uses the last commit time) and repeated runs are byte-identical.

With autotools:

```sh
make sbom
```

This requires `python3` and `pyspdxtools` (`pip install spdx-tools`). The generator ships in the tree, so `make sbom` does not need a separate wolfSSL checkout. Pass `WOLFSSL_DIR=/path/to/wolfssl` when pkg-config cannot see the wolfSSL that this build linked, so the dependency version is read from `wolfssl/version.h`. `SBOM_WOLFSSL_VERSION` overrides that detection.

The CMake build exposes the same target. `WOLFSSL_DIR` is optional and has the same meaning:

```sh
cmake -B build .
cmake --build build --target sbom
```

The output files are:

- `wolftpm-<version>.cdx.json`
- `wolftpm-<version>.spdx.json`
- `wolftpm-<version>.spdx`

Optional overrides:

| Variable | Purpose |
|---|---|
| `SBOM_LICENSE_OVERRIDE` | SPDX expression to use instead of the licence parsed from `COPYING` (for example `LicenseRef-wolfSSL-Commercial` for commercial licensees). Defaults to `GPL-3.0-or-later`, the per-file header licence. |
| `SBOM_LICENSE_TEXT` | Path to the licence text for any `LicenseRef-*` used in `SBOM_LICENSE_OVERRIDE` (required by SPDX 2.3). |
| `SBOM_WOLFSSL_VERSION` | Version recorded for the wolfSSL dependency. Auto-detected from `WOLFSSL_DIR/wolfssl/version.h` (or the wolfSSL `pkg-config` entry) when unset. |

To install the generated files:

```sh
make install-sbom    # installs to $(datadir)/doc/wolftpm/
make uninstall-sbom
```

For further CRA guidance see [wolfssl/doc/CRA.md](https://github.com/wolfSSL/wolfssl/blob/master/doc/CRA.md).

## Generator internals

The `share/` set of wolfGlass is the only vendorable part. The `tools/wolfglass-sync` script copies these files into a product at `tools/sbom/`, together with the pin files (`VERSION` and `.wolfglass-rev`). Copy the files, not the `share/` folder name.

### Contents

| File | Role |
|---|---|
| `sbom-driver.py` | The product-neutral SBOM engine (Python). |
| `sbom-driver` | Thin shell wrapper that runs `sbom-driver.py`. |
| `validate_sbom.py` | Structural validator for CI (`--name-prefix`). |
| `frontends/compdb_sbom.py` | Extractor for any `compile_commands.json`. |
| `frontends/iar_sbom.py` | Extractor for an IAR Embedded Workbench `.ewp`. |
| `frontends/zephyr_sbom.py` | Extractor for a Zephyr module `CMakeLists.txt`. |
| `build/sbom.mk` | Shared plain-Make fragment and `wolfglass_sbom_rule` macro. |
| `build/sbom.cmake` | Shared CMake helper: `wolfglass_add_sbom()`. |
| `gen-sbom` | The vendored SBOM generator. |
| `sbom.am` | Shared autotools fragment. |

### The driver contract

Every front end produces a composition input and a config input and hands them to the driver.

Composition (at least one):

- `--srcs-file PATH`: the source files compiled into the artifact (tier E).
- `--lib PATH`: the built library to hash (tier R/L/S).
- `--no-artifact-hash`: record the artifact as-built and do not re-hash. Use it with `--lib` for a FIPS canister or a kernel module. Never substitute a source list for a certified artifact.

Config (choose one):

- `--cflags="..."`: raw CFLAGS. The driver expands the `-D` tokens through the host compiler. Use the `=` form so a leading-dash value is not read as a flag.
- `--options-h PATH`: a pre-expanded flat `#define` header, used verbatim.
- `--user-settings PATH`: a `user_settings.h`, which the generator captures.
- `--source-only`: no build-config macros (for example a Kconfig-driven build).

Dependency (for linkers and bindings): `--dep-wolfssl`, `--dep-openssl`, and `--dep-version` are passed through only when the generator supports them.

The driver captures macros with the host compiler, so the SBOM is reproducible across toolchains. It scrubs absolute host paths from the captured macros unless you pass `--no-scrub`.

The shared driver is product-neutral and calls the vendored `share/gen-sbom` by default. Pass `--gen-sbom` only when you want to override that copy.

### The manifest contract

A product does not copy logic. It describes itself:

- **Make:** set `SBOM_NAME`, `SBOM_SRCS`, `SBOM_CFLAGS`, and a version (`SBOM_VERSION`, or `SBOM_VERSION_FILE` and `SBOM_VERSION_MACRO`), then `include tools/sbom/build/sbom.mk`. For a second target, instantiate `$(eval $(call wolfglass_sbom_rule,<target>,<prefix>))`. If the product configuration lives in a `user_settings.h`, also set `SBOM_SETTINGS_H` (and `SBOM_INCLUDE_DIRS` if that header needs paths the CFLAGS do not already carry). `SBOM_CFLAGS` alone records the literal `-D` set and nothing it derives, which for a gated header means the SBOM describes a configuration nobody built.
- **CMake:** `include(tools/sbom/build/sbom.cmake)` and call `wolfglass_add_sbom()` with `NAME`, `VERSION_FILE`, `VERSION_MACRO`, `TARGETS`, `DEFS`, `LICENSE`. `SBOM_GEN` is the canonical generator override. `GEN_SBOM` remains a legacy alias for compatibility.
- **Autotools:** set the `SBOM_*` variables and `include tools/sbom/sbom.am`.

Keep only true product knowledge in the product: the route-through script, the module extractor, and the HAL source selector.

## See Also

- [Testing and CI](testing.md)
- [Release Notes](release-notes.md)
- [API Reference](api-reference.md)
