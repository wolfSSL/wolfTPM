# wolfTPM Rust wrapper

[![crates.io](https://img.shields.io/crates/v/wolftpm.svg)](https://crates.io/crates/wolftpm)
[![docs.rs](https://docs.rs/wolftpm/badge.svg)](https://docs.rs/wolftpm)

Official Rust bindings for wolfTPM. The crate lives in [`wolftpm/`](wolftpm/);
see its [README](wolftpm/README.md) for the full API, build, and test details.

```sh
# 1. build the C library first (with a software TPM for testing)
cd ../..                       # wolfTPM repo root
./autogen.sh && ./configure --enable-swtpm --enable-fwtpm && make

# 2. build, lint, and document the Rust crate against it
make -C wrapper/rust

# 3. test (needs a running software TPM on localhost:2321)
make -C wrapper/rust test
```
