//! Build script for the `wolftpm` crate.
//!
//! Mirrors the official `wolfssl-wolfcrypt` build.rs: it does NOT build the C
//! library, it links a pre-built one. Order of operations:
//!   1. bindgen over `headers.h` -> $OUT_DIR/bindings.rs
//!   2. link libwolftpm (+ its libwolfssl dependency)
//!   3. scan_cfg: emit cfgs for what the C library was actually built with

extern crate bindgen;

use regex::Regex;
use std::env;
use std::fs;
use std::io::{self, Read, Result};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(e) = run_build() {
        eprintln!("Build failed: {}", e);
        std::process::exit(1);
    }
}

fn run_build() -> Result<()> {
    println!("cargo:rerun-if-env-changed=WOLFTPM_PREFIX");
    println!("cargo:rerun-if-env-changed=WOLFSSL_PREFIX");
    generate_bindings()?;
    setup_link()?;
    scan_cfg()?;
    scan_options()?;
    Ok(())
}

fn crate_dir() -> Result<String> {
    Ok(env::current_dir()?.display().to_string())
}

/// wolfTPM repo root, assuming this crate lives at `wrapper/rust/wolftpm`.
fn wolftpm_repo_base_dir() -> Result<String> {
    Ok(format!("{}/../../..", crate_dir()?))
}

fn wolftpm_repo_lib_dir() -> Result<String> {
    Ok(format!("{}/src/.libs", wolftpm_repo_base_dir()?))
}

/// Read and validate a `*_PREFIX` env var.
fn user_prefix(var: &str) -> Option<String> {
    match env::var(var) {
        Ok(prefix) if !prefix.is_empty() && !prefix.contains('\n') => Some(prefix),
        Ok(_) => {
            println!("cargo:warning=ignoring {}", var);
            None
        }
        Err(_) => None,
    }
}

/// Include dir holding `wolftpm/options.h`. `WOLFTPM_PREFIX/include`, else the
/// in-tree repo root when configured.
fn wolftpm_include_dir() -> Result<Option<String>> {
    if let Some(prefix) = user_prefix("WOLFTPM_PREFIX") {
        let inc = format!("{}/include", prefix);
        if Path::new(&inc).join("wolftpm").is_dir() {
            return Ok(Some(inc));
        }
        return Err(io::Error::other(format!(
            "WOLFTPM_PREFIX is set but {}/wolftpm is missing",
            inc
        )));
    }
    let base = wolftpm_repo_base_dir()?;
    if Path::new(&base).join("wolftpm/options.h").is_file() {
        Ok(Some(base))
    } else {
        Ok(None)
    }
}

/// Include dir holding `wolfssl/options.h`. `WOLFSSL_PREFIX/include`, else a
/// sibling `../wolfssl` source checkout when present.
fn wolfssl_include_dir() -> Result<Option<String>> {
    if let Some(prefix) = user_prefix("WOLFSSL_PREFIX") {
        let inc = format!("{}/include", prefix);
        if Path::new(&inc).join("wolfssl").is_dir() {
            return Ok(Some(inc));
        }
        return Err(io::Error::other(format!(
            "WOLFSSL_PREFIX is set but {}/wolfssl is missing",
            inc
        )));
    }
    if let Some(inc) = pkg_config_var("--variable=includedir") {
        if Path::new(&inc).join("wolfssl").is_dir() {
            return Ok(Some(inc));
        }
    }
    // in-repo `./wolfssl` (the wolfTPM CI layout) then a sibling checkout
    let base = wolftpm_repo_base_dir()?;
    for cand in [format!("{}/wolfssl", base), format!("{}/../wolfssl", base)] {
        if Path::new(&cand).join("wolfssl/options.h").is_file() {
            return Ok(Some(cand));
        }
    }
    Ok(None)
}

/// Library dir for libwolfssl. `WOLFSSL_PREFIX/lib`, else pkg-config's libdir,
/// else a sibling `../wolfssl` build output. Prefer the installed copy that
/// libwolftpm was actually linked against over a feature-reduced checkout.
fn wolfssl_lib_dir() -> Result<Option<String>> {
    if let Some(prefix) = user_prefix("WOLFSSL_PREFIX") {
        let dir = format!("{}/lib", prefix);
        if Path::new(&dir).is_dir() {
            return Ok(Some(dir));
        }
        return Err(io::Error::other(format!(
            "WOLFSSL_PREFIX is set but {} is missing",
            dir
        )));
    }
    if let Some(dir) = pkg_config_var("--variable=libdir") {
        if Path::new(&dir).exists() {
            return Ok(Some(dir));
        }
    }
    let base = wolftpm_repo_base_dir()?;
    for cand in [
        format!("{}/wolfssl/src/.libs", base),
        format!("{}/../wolfssl/src/.libs", base),
    ] {
        if Path::new(&cand).exists() {
            return Ok(Some(cand));
        }
    }
    Ok(None)
}

/// Query a pkg-config variable for wolfssl, without a build dependency.
fn pkg_config_var(flag: &str) -> Option<String> {
    let out = std::process::Command::new("pkg-config")
        .args([flag, "wolfssl"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn lib_dir(prefix_var: &str, in_tree: Option<String>) -> Result<Option<String>> {
    if let Some(prefix) = user_prefix(prefix_var) {
        let dir = format!("{}/lib", prefix);
        if Path::new(&dir).is_dir() {
            return Ok(Some(dir));
        }
        return Err(io::Error::other(format!(
            "{} is set but {} is missing",
            prefix_var, dir
        )));
    }
    match in_tree {
        Some(dir) if Path::new(&dir).exists() => Ok(Some(dir)),
        _ => Ok(None),
    }
}

fn bindings_path() -> String {
    PathBuf::from(env::var("OUT_DIR").unwrap())
        .join("bindings.rs")
        .display()
        .to_string()
}

fn generate_bindings() -> Result<()> {
    let mut builder = bindgen::Builder::default()
        .header("headers.h")
        // The raw FFI layer needs neither libc decls nor the C doxygen text;
        // both only produce warnings (libc memcpy/etc. trip the runtime-symbol
        // lint, and doxygen [in,out]/[0] markers become broken rustdoc links).
        .blocklist_function("memcpy")
        .blocklist_function("memmove")
        .blocklist_function("memset")
        .blocklist_function("memcmp")
        .blocklist_function("bcmp")
        .blocklist_function("strlen")
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    // Preprocess for the actual target, not the build host: wolfTPM headers
    // select struct fields and transports on __linux__/_WIN32/arch macros, so a
    // host/target mismatch would generate the wrong FFI layout when cross-compiling.
    if let Ok(target) = env::var("TARGET") {
        builder = builder.clang_arg(format!("--target={}", target));
    }

    if let Some(inc) = wolftpm_include_dir()? {
        builder = builder.clang_arg(format!("-I{}", inc));
    }
    if let Some(inc) = wolfssl_include_dir()? {
        builder = builder.clang_arg(format!("-I{}", inc));
    }

    let bindings = builder
        .generate()
        .map_err(|_| io::Error::other("Failed to generate bindings"))?;
    bindings
        .write_to_file(bindings_path())
        .map_err(|e| io::Error::other(format!("Couldn't write bindings: {}", e)))
}

/// Emit link directives for one library, preferring shared then static.
fn link_one(name: &str, dir: &Option<String>) {
    let target = env::var("TARGET").unwrap();
    let is_windows = target.contains("windows");
    if let Some(dir) = dir {
        println!("cargo:rustc-link-search={}", dir);
        let p = Path::new(dir);
        let shared = p.join(format!("lib{}.so", name)).exists()
            || p.join(format!("lib{}.dylib", name)).exists()
            || p.join(format!("{}.dll", name)).exists()
            || p.join(format!("{}.lib", name)).exists();
        if shared {
            println!("cargo:rustc-link-lib={}", name);
            // rpath is a GNU ld concept; skip it for MSVC and bare-metal targets.
            if !is_windows && !target.ends_with("-none-elf") {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir);
            }
        } else {
            println!("cargo:rustc-link-lib=static={}", name);
        }
    } else {
        println!("cargo:rustc-link-lib={}", name);
    }
}

/// Whether a directory actually holds a `wolftpm` library to link, across the
/// Unix (`lib` prefix) and Windows (MSVC/MinGW) naming conventions.
fn has_wolftpm_lib(dir: &str) -> bool {
    let p = Path::new(dir);
    [
        "libwolftpm.so",
        "libwolftpm.a",
        "libwolftpm.dylib",
        "wolftpm.lib",     // MSVC static / import library
        "wolftpm.dll",     // MSVC shared
        "libwolftpm.dll.a", // MinGW import library
    ]
    .iter()
    .any(|name| p.join(name).exists())
}

fn setup_link() -> Result<()> {
    let wolftpm_libs = lib_dir("WOLFTPM_PREFIX", Some(wolftpm_repo_lib_dir()?))?;
    // Fail closed: the bindings were generated from a specific wolftpm/options.h,
    // and wolfTPM struct layouts are configuration dependent (e.g. WOLFTPM_SPDM
    // grows WOLFTPM2_DEV). Require an actual libwolftpm in the resolved directory
    // rather than falling back to a bare `-l wolftpm` that could pull in a
    // system library built with a different configuration than the headers.
    match &wolftpm_libs {
        Some(dir) if has_wolftpm_lib(dir) => {}
        _ => {
            return Err(io::Error::other(format!(
                "no libwolftpm to link ({}); build wolfTPM in-tree (src/.libs) or set \
                 WOLFTPM_PREFIX to an install whose headers match the library",
                wolftpm_libs.as_deref().unwrap_or("in-tree src/.libs missing"),
            )));
        }
    }
    let wolfssl_libs = wolfssl_lib_dir()?;
    link_one("wolftpm", &wolftpm_libs);
    link_one("wolfssl", &wolfssl_libs);
    Ok(())
}

fn read_file(path: String) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn check_cfg(binding: &str, symbol: &str, cfg_name: &str) -> bool {
    let re = Regex::new(&format!(r"\b{}\b", regex::escape(symbol))).unwrap();
    println!("cargo::rustc-check-cfg=cfg({})", cfg_name);
    if re.is_match(binding) {
        println!("cargo:rustc-cfg={}", cfg_name);
        true
    } else {
        false
    }
}

/// Emit cfgs describing how the linked libwolftpm was actually built, so the
/// safe modules can gate on real availability rather than Cargo features.
fn scan_cfg() -> Result<()> {
    let binding = read_file(bindings_path())?;

    // high-level wolfTPM2 wrapper present (i.e. not WOLFTPM2_NO_WRAPPER)
    check_cfg(&binding, "wolfTPM2_Init", "wrapper");
    // human-readable return-code strings
    check_cfg(&binding, "TPM2_GetRCString", "rc_string");
    // optional capabilities
    check_cfg(&binding, "wolfTPM2_SetCryptoDevCb", "crypto_cb");
    check_cfg(&binding, "wolfTPM2_CreateKeySeal", "seal");
    check_cfg(&binding, "wolfTPM2_NVCreateAuth", "nv");
    check_cfg(&binding, "wolfTPM2_ReadPCR", "pcr");
    check_cfg(&binding, "wolfTPM2_GetRandom", "rng");
    check_cfg(&binding, "wolfTPM2_RsaEncrypt", "rsa");
    check_cfg(&binding, "wolfTPM2_NVStoreKey", "persist");
    check_cfg(&binding, "wolfTPM2_ExportPublicKeyBuffer", "pubexport");
    check_cfg(&binding, "wolfTPM2_HmacStart", "hmac");
    // self-test + capability query
    check_cfg(&binding, "wolfTPM2_GetCapabilities", "caps");
    // TPM-resident keyed-hash HMAC key (create/load-once)
    check_cfg(&binding, "wolfTPM2_GetKeyTemplate_KeyedHash", "keyedhash");
    // symmetric AES encrypt/decrypt
    check_cfg(&binding, "wolfTPM2_EncryptDecrypt", "symmetric");
    // ECDH key agreement
    check_cfg(&binding, "wolfTPM2_ECDHGen", "ecdh");
    // external RSA/ECC private-key import
    check_cfg(&binding, "wolfTPM2_ImportRsaPrivateKey", "import");
    // certificate read from an NV index (EK cert)
    check_cfg(&binding, "wolfTPM2_NVReadCert", "nvcert");
    // EK policy session for credential activation
    check_cfg(&binding, "wolfTPM2_CreateAuthSession_EkPolicy", "ek_policy");

    Ok(())
}

/// Emit cfgs for build-flag macros that are `#define`-only (no bindable
/// symbol), read straight from the linked library's `wolftpm/options.h`.
fn scan_options() -> Result<()> {
    let inc = match wolftpm_include_dir()? {
        Some(d) => d,
        None => return Ok(()),
    };
    let text = fs::read_to_string(format!("{}/wolftpm/options.h", inc)).unwrap_or_default();

    let flag = |macro_name: &str, cfg_name: &str| {
        println!("cargo::rustc-check-cfg=cfg({})", cfg_name);
        let re =
            Regex::new(&format!(r"(?m)^\s*#\s*define\s+{}\b", regex::escape(macro_name))).unwrap();
        if re.is_match(&text) {
            println!("cargo:rustc-cfg={}", cfg_name);
        }
    };
    flag("WOLFTPM_SWTPM", "swtpm");
    flag("WOLFTPM_LINUX_DEV", "devtpm");
    flag("WOLFTPM_MMIO", "mmio");
    flag("WOLFTPM_FWTPM", "fwtpm");
    // Callback-free transports: Windows TBS and Linux kernel-device autodetect.
    flag("WOLFTPM_WINAPI", "winapi");
    flag("WOLFTPM_LINUX_DEV_AUTODETECT", "linux_autodetect");
    // Autoconf's --enable-autodetect records WOLFTPM_AUTODETECT; on a Linux
    // target the headers derive WOLFTPM_LINUX_DEV_AUTODETECT (a callback-free
    // kernel-device transport), so treat that as linux_autodetect too. On
    // non-Linux targets WOLFTPM_AUTODETECT is the SPI/I2C HAL autodetect, which
    // needs a callback and must not enable the callback-free open().
    if env::var("TARGET").unwrap_or_default().contains("linux") {
        let re = Regex::new(r"(?m)^\s*#\s*define\s+WOLFTPM_AUTODETECT\b").unwrap();
        if re.is_match(&text) {
            println!("cargo:rustc-cfg=linux_autodetect");
        }
    }
    Ok(())
}
