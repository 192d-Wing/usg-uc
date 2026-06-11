package org.usg.sipclient

import android.content.Context
import org.json.JSONObject
import uniffi.client_ffi.SipAccountConfig
import uniffi.client_ffi.TransportKind

/**
 * Debug-only account seeding for a fresh app sandbox (emulator / clean install).
 *
 * A real device build authenticates with a CAC/PIV-derived credential and a
 * user-configured account. A fresh emulator has neither, so registration can't
 * happen without typing the account in by hand on every clean install.
 *
 * To avoid that friction during development — and WITHOUT ever committing
 * credentials — this loads a **gitignored** `DevSeed.json` from the app's
 * assets. It runs only in DEBUG builds, only when no account is already
 * configured. If the asset is absent, seeding is silently skipped.
 *
 * Create `app/src/main/assets/DevSeed.json` locally:
 * ```json
 * {
 *   "displayName": "John",
 *   "sipUri": "sip:user@sip.example.com",
 *   "registrarUri": "sip:sip.example.com",
 *   "transport": "udp",
 *   "callerId": "+15555550123",
 *   "username": "user",
 *   "password": "secret"
 * }
 * ```
 */
object DevSeed {
    data class Payload(
        val displayName: String,
        val sipUri: String,
        val registrarUri: String,
        val transport: String,
        val callerId: String?,
        val username: String,
        val password: String,
    )

    /** Loads the gitignored seed payload, or null if absent/unreadable. */
    fun load(context: Context): Payload? = runCatching {
        val text = context.assets.open("DevSeed.json").bufferedReader().use { it.readText() }
        val o = JSONObject(text)
        Payload(
            displayName = o.getString("displayName"),
            sipUri = o.getString("sipUri"),
            registrarUri = o.getString("registrarUri"),
            transport = o.optString("transport", "udp"),
            callerId = o.optString("callerId").ifEmpty { null },
            username = o.getString("username"),
            password = o.getString("password"),
        )
    }.getOrNull()

    private fun transportKind(raw: String): TransportKind = when (raw.lowercase()) {
        "tls" -> TransportKind.TLS
        "tcp" -> TransportKind.TCP
        else -> TransportKind.UDP
    }

    /** Builds the FFI account config from the payload. */
    fun account(p: Payload): SipAccountConfig = SipAccountConfig(
        id = "default",
        displayName = p.displayName,
        sipUri = p.sipUri,
        registrarUri = p.registrarUri,
        transport = transportKind(p.transport),
        registerExpiry = 3600u,
        enabled = true,
        callerId = p.callerId,
        digestUsername = p.username,
    )
}
