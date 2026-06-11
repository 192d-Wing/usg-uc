//! Android JNI initialization shim.
//!
//! UniFFI loads the library through JNA (`dlopen`), which does not invoke
//! `JNI_OnLoad`, so the Rust core never receives the `JavaVM`. Several
//! dependencies need the Android context via the `ndk_context` crate —
//! `cpal` device enumeration and `hickory-resolver` DNS both call
//! `ndk_context::android_context()` and panic if it was never initialized.
//!
//! The Kotlin app must call this once, before constructing `SipClient`:
//!
//! ```kotlin
//! object RustAndroid {
//!     init { System.loadLibrary("client_ffi") }
//!     external fun initAndroidContext(context: Context)
//! }
//! // Application.onCreate or before the first SipClient():
//! RustAndroid.initAndroidContext(applicationContext)
//! ```
//!
//! `System.loadLibrary` is required so the JVM can resolve this `external fun`
//! to the exported symbol below; JNA having already `dlopen`ed the same `.so`
//! is harmless (idempotent).

use jni::JNIEnv;
use jni::objects::{JClass, JObject};
use std::ffi::c_void;

/// Initializes `ndk_context` with the JVM and application `Context`.
///
/// Exported as `org.usg.sipclient.RustAndroid.initAndroidContext(Context)`.
/// The `Context` global ref is intentionally leaked so it lives for the
/// process lifetime (the audio/DNS subsystems may query it at any time).
///
/// # Safety
/// Called by the JVM with valid JNI arguments. Idempotent-safe: re-init just
/// overwrites the stored pointers with equivalent ones.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_usg_sipclient_RustAndroid_initAndroidContext(
    mut env: JNIEnv,
    _class: JClass,
    context: JObject,
) {
    let Ok(vm) = env.get_java_vm() else {
        tracing::error!("initAndroidContext: could not obtain JavaVM");
        return;
    };
    let Ok(context_ref) = env.new_global_ref(&context) else {
        tracing::error!("initAndroidContext: could not pin Context global ref");
        return;
    };
    // SAFETY: `vm` and the global Context ref are valid for the process
    // lifetime (the ref is leaked below); ndk_context just stores the pointers.
    unsafe {
        ndk_context::initialize_android_context(
            vm.get_java_vm_pointer().cast::<c_void>(),
            context_ref.as_raw().cast::<c_void>(),
        );
    }
    // Keep the Context alive forever; ndk_context holds a raw pointer to it.
    std::mem::forget(context_ref);
    tracing::info!("Android context initialized for ndk_context consumers");
}
