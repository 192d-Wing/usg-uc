package org.usg.sipclient

import android.content.Context

/**
 * Hands the Rust core the Android JavaVM + Context via JNI.
 *
 * UniFFI loads the native library through JNA (`dlopen`), which never invokes
 * `JNI_OnLoad`, so the Rust side otherwise has no `JavaVM`. Dependencies that
 * call `ndk_context::android_context()` (cpal device enumeration,
 * hickory-resolver DNS) panic without it. Call [initAndroidContext] once with
 * the application context before constructing the SIP client.
 *
 * `System.loadLibrary` is required so the JVM can resolve the `external fun`
 * to the exported Rust symbol; JNA having already loaded the same `.so` is
 * harmless.
 */
object RustAndroid {
    @Volatile private var initialized = false

    init {
        System.loadLibrary("client_ffi")
    }

    /** Native: implemented in client-ffi/src/android.rs. */
    external fun initAndroidContext(context: Context)

    /** Idempotent: initializes the Android context exactly once. */
    @Synchronized
    fun ensureInitialized(context: Context) {
        if (initialized) return
        initAndroidContext(context.applicationContext)
        initialized = true
    }
}
