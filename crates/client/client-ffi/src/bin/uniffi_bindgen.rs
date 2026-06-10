//! Binding-generator CLI for the client FFI layer.
//!
//! Generates Swift/Kotlin sources from the compiled library, e.g.:
//! `cargo run -p client-ffi --features bindgen --bin uniffi-bindgen -- \
//!     generate --library target/debug/libclient_ffi.dylib --language swift --out-dir out/`

fn main() {
    uniffi::uniffi_bindgen_main();
}
