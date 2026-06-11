//! Build script for client-ffi.
//!
//! On Android, the Oboe backend (oboe-sys) compiles C++ but does not link the
//! C++ runtime — it expects the final binary to provide it. As a cdylib, this
//! crate IS that final binary, so we link libc++_shared here: without it the
//! `.so` fails to resolve `__cxa_pure_virtual` (and other C++ ABI symbols) at
//! load. The matching `libc++_shared.so` is staged into jniLibs by
//! `clients/android/build-rust.sh` so the dynamic linker finds it at runtime.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    }
}
