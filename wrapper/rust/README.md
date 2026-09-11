# wolfTPM Rust wrapper

Official Rust bindings for wolfTPM. The crate lives in [`wolftpm/`](wolftpm/);
see its [README](wolftpm/README.md) for the full API, build, and test details.

```sh
# 1. build the C library first (with a software TPM for testing)
cd ../..                       # wolfTPM repo root
./autogen.sh && ./configure --enable-swtpm --enable-fwtpm && make

# 2. build the Rust crate against it
cd wrapper/rust/wolftpm
cargo build

# 3. test (needs a running software TPM on localhost:2321)
cargo test --features swtpm-tests -- --test-threads=1
```
