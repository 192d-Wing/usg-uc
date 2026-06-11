package org.usg.sipclient

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import org.usg.sipclient.ui.RootScreen
import org.usg.sipclient.ui.UsgTheme
import uniffi.client_ffi.initLogging

/**
 * Single-activity host. Mirrors SipClientApp.swift: it initializes Rust logging,
 * requests the microphone permission, drives the AudioManager call mode off the
 * call state, and hosts the Compose UI bound to [AppViewModel].
 */
class MainActivity : ComponentActivity() {

    private val model: AppViewModel by viewModels()

    private val requestMic =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* started regardless */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Route the Rust core's stderr (where tracing-subscriber writes) into
        // logcat, then initialize Rust logging. RUST_LOG is honored; the default
        // filter is info for the client crates.
        LogcatBridge.install()
        initLogging(null)

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            requestMic.launch(Manifest.permission.RECORD_AUDIO)
        }

        // Start the core (constructs SipClient, registers the listener). The
        // ViewModel does all FFI work off the main thread.
        model.start()

        setContent {
            UsgTheme {
                // Drive the audio mode off the active-call state. MODE_IN_COMMUNICATION
                // is the VoIP profile; documented here for when the Oboe backend lands
                // (today the Rust audio path has no usable Android backend yet).
                val activeCall by model.activeCall.collectAsState()
                val incoming by model.incomingCall.collectAsState()
                setCommunicationMode(activeCall != null || incoming != null)

                RootScreen(model)
            }
        }
    }

    /** Toggle MODE_IN_COMMUNICATION for the duration of a call. */
    private fun setCommunicationMode(inCall: Boolean) {
        val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        am.mode = if (inCall) AudioManager.MODE_IN_COMMUNICATION else AudioManager.MODE_NORMAL
    }
}
