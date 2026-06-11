package org.usg.sipclient

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.client_ffi.AppEvent
import uniffi.client_ffi.AudioDevice
import uniffi.client_ffi.AudioSettings
import uniffi.client_ffi.CallInfo
import uniffi.client_ffi.CallHistoryEntry
import uniffi.client_ffi.CallState
import uniffi.client_ffi.ClassificationBanner
import uniffi.client_ffi.ClientConfig
import uniffi.client_ffi.CodecKind
import uniffi.client_ffi.Contact
import uniffi.client_ffi.EventListener
import uniffi.client_ffi.PhoneNumber
import uniffi.client_ffi.RegistrationState
import uniffi.client_ffi.SipAccountConfig
import uniffi.client_ffi.SipClient
import uniffi.client_ffi.listInputDevices
import uniffi.client_ffi.listOutputDevices

/** A ringing inbound call that has not been answered or rejected yet. */
data class RingingCall(
    val id: String,
    val remoteUri: String,
    val displayName: String?,
)

/**
 * Bridges the Rust SIP core (client-ffi UniFFI bindings) to Compose. Ports
 * AppModel.swift's threading contract:
 *   - Every FFI call blocks on the Rust runtime, so all of them run on
 *     [Dispatchers.IO] — never the main thread.
 *   - The [client] field is only touched from coroutines launched here.
 *   - All StateFlow values are mutated on the main dispatcher only.
 *   - Rust pushes events on a runtime worker thread; [Listener] hops to main
 *     (via [Dispatchers.Main]) before touching state.
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {

    // region StateFlow (mutated on the main dispatcher only)
    private val _registration = MutableStateFlow<RegistrationState?>(null)
    val registration: StateFlow<RegistrationState?> = _registration.asStateFlow()

    private val _registrationText = MutableStateFlow("not started")
    val registrationText: StateFlow<String> = _registrationText.asStateFlow()

    private val _activeCall = MutableStateFlow<CallInfo?>(null)
    val activeCall: StateFlow<CallInfo?> = _activeCall.asStateFlow()

    private val _incomingCall = MutableStateFlow<RingingCall?>(null)
    val incomingCall: StateFlow<RingingCall?> = _incomingCall.asStateFlow()

    private val _isMuted = MutableStateFlow(false)
    val isMuted: StateFlow<Boolean> = _isMuted.asStateFlow()

    private val _isOnHold = MutableStateFlow(false)
    val isOnHold: StateFlow<Boolean> = _isOnHold.asStateFlow()

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts.asStateFlow()

    private val _recents = MutableStateFlow<List<CallHistoryEntry>>(emptyList())
    val recents: StateFlow<List<CallHistoryEntry>> = _recents.asStateFlow()

    private val _account = MutableStateFlow<SipAccountConfig?>(null)
    val account: StateFlow<SipAccountConfig?> = _account.asStateFlow()

    private val _audioSettings = MutableStateFlow<AudioSettings?>(null)
    val audioSettings: StateFlow<AudioSettings?> = _audioSettings.asStateFlow()

    private val _inputDevices = MutableStateFlow<List<AudioDevice>>(emptyList())
    val inputDevices: StateFlow<List<AudioDevice>> = _inputDevices.asStateFlow()

    private val _outputDevices = MutableStateFlow<List<AudioDevice>>(emptyList())
    val outputDevices: StateFlow<List<AudioDevice>> = _outputDevices.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _classificationBanner = MutableStateFlow<ClassificationBanner?>(null)
    val classificationBanner: StateFlow<ClassificationBanner?> = _classificationBanner.asStateFlow()

    // endregion

    /** Only accessed from coroutines on [Dispatchers.IO]. */
    private var client: SipClient? = null
    private var started = false

    /** Constructs and starts the client. Safe to call repeatedly. */
    fun start() {
        if (started) return
        started = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val ctx = getApplication<Application>()
                // Give the Rust core the JavaVM + Context before anything that
                // uses ndk_context (cpal device enumeration, hickory DNS).
                RustAndroid.ensureInitialized(ctx)
                // Android has no directories-crate default: pass the app sandbox
                // paths explicitly, or settings/contacts persistence fails.
                val cfg = ClientConfig(
                    sipListenAddr = "0.0.0.0:5060",
                    mediaAddr = "0.0.0.0:16384",
                    configDir = ctx.filesDir.resolve("config").apply { mkdirs() }.absolutePath,
                    dataDir = ctx.filesDir.resolve("data").apply { mkdirs() }.absolutePath,
                    preferIpv6 = false,
                )
                val c = SipClient(cfg)
                c.setEventListener(Listener())
                c.initialize()
                client = c
                setMain { _registrationText.value = "initialized" }
                seedAccountIfNeeded(c)
                refreshAll()
            } catch (e: Exception) {
                setMain { _errorMessage.value = e.toString() }
            }
        }
    }

    /**
     * DEBUG-only: seed a dev account from the gitignored assets/DevSeed.json
     * when no account is configured (fresh install), then register. No-op in
     * release, when an account already exists, or when the asset is absent.
     */
    private suspend fun seedAccountIfNeeded(c: SipClient) {
        if (!BuildConfig.DEBUG) return
        if (c.getAccount() != null) return
        val seed = DevSeed.load(getApplication()) ?: return
        try {
            c.updateAccount(DevSeed.account(seed), seed.password)
            c.register()
            setMain { _registrationText.value = "seeded; registering…" }
        } catch (e: Exception) {
            setMain { _errorMessage.value = "seed failed: $e" }
        }
    }

    // region FFI plumbing
    /** Runs an FFI call on IO; errors surface as the error banner. */
    private fun run(body: suspend (SipClient) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val c = client ?: return@launch
            try {
                body(c)
            } catch (e: Exception) {
                setMain { _errorMessage.value = e.toString() }
            }
        }
    }

    /** Runs an FFI query on IO and publishes the result on main. */
    private fun <T> fetch(body: (SipClient) -> T, publish: (T) -> Unit) {
        run { c ->
            val value = body(c)
            setMain { publish(value) }
        }
    }

    private suspend fun setMain(block: () -> Unit) = withContext(Dispatchers.Main) { block() }
    // endregion

    // region Calls
    fun call(target: String) {
        val trimmed = target.trim()
        if (trimmed.isEmpty()) return
        run { it.makeCall(trimmed) }
    }

    fun hangup() = run { it.hangup() }

    fun answer() {
        val id = _incomingCall.value?.id ?: return
        run { it.acceptIncomingCall(id) }
    }

    fun reject() {
        val id = _incomingCall.value?.id ?: return
        _incomingCall.value = null
        run { it.rejectIncomingCall(id) }
    }

    fun sendDtmf(digit: String) = run { it.sendDtmf(digit) }

    fun toggleMute() = fetch({ it.toggleMute() }) { _isMuted.value = it }

    fun toggleHold() = fetch({ it.toggleHold() }) { _isOnHold.value = it }
    // endregion

    // region Contacts
    fun refreshContacts() = fetch({ it.listContacts() }) { _contacts.value = it }

    fun addContact(name: String, sipUri: String, phoneNumbers: List<PhoneNumber>) {
        run { it.addContact(name, sipUri, phoneNumbers) }
        refreshContacts()
    }

    fun updateContact(contact: Contact) {
        run { it.updateContact(contact) }
        refreshContacts()
    }

    fun removeContact(id: String) {
        run { it.removeContact(id) }
        refreshContacts()
    }
    // endregion

    // region Recents
    fun refreshRecents() = fetch({ it.callHistory(200u) }) { _recents.value = it }

    fun clearRecents() {
        run { it.clearCallHistory() }
        refreshRecents()
    }
    // endregion

    // region Account / registration
    fun refreshAccount() = fetch({ it.getAccount() }) { _account.value = it }

    /** Persists the account (and password if non-empty), then re-registers when enabled. */
    fun saveAccount(account: SipAccountConfig, digestPassword: String) {
        run { c ->
            val password = digestPassword.ifEmpty { null }
            c.updateAccount(account, password)
            if (account.enabled) c.register()
        }
        refreshAccount()
    }

    fun registerNow() = run { it.register() }
    fun unregisterNow() = run { it.unregister() }
    // endregion

    // region Audio
    fun refreshAudio() {
        fetch({ it.getAudioSettings() }) { _audioSettings.value = it }
        // Device enumeration is a free function (not on SipClient); on Android
        // CPAL has no usable backend yet, so this returns empty/errs gracefully.
        fetch({ runCatching { listInputDevices() }.getOrDefault(emptyList()) }) {
            _inputDevices.value = it
        }
        fetch({ runCatching { listOutputDevices() }.getOrDefault(emptyList()) }) {
            _outputDevices.value = it
        }
    }

    fun selectInputDevice(name: String?) {
        val inCall = _activeCall.value != null
        run { c ->
            val settings = c.getAudioSettings().copy(inputDevice = name)
            c.updateAudioSettings(settings)
            if (inCall) c.switchInputDevice(name)
        }
        refreshAudio()
    }

    fun selectOutputDevice(name: String?) {
        val inCall = _activeCall.value != null
        run { c ->
            val settings = c.getAudioSettings().copy(outputDevice = name)
            c.updateAudioSettings(settings)
            if (inCall) c.switchOutputDevice(name)
        }
        refreshAudio()
    }

    fun selectCodec(codec: CodecKind) {
        run { c ->
            val settings = c.getAudioSettings().copy(preferredCodec = codec)
            c.updateAudioSettings(settings)
        }
        refreshAudio()
    }
    // endregion

    fun dismissError() {
        _errorMessage.value = null
    }

    private fun refreshAll() {
        refreshContacts()
        refreshRecents()
        refreshAccount()
        refreshAudio()
        fetch({ it.classificationBanner() }) { _classificationBanner.value = it }
        fetch({ it.registrationState() }) { state ->
            if (state != null) {
                _registration.value = state
                _registrationText.value = describe(state)
            }
        }
    }

    // region Events (already hopped to main by Listener)
    private fun handle(event: AppEvent) {
        when (event) {
            is AppEvent.RegistrationStateChanged -> {
                _registration.value = event.state
                _registrationText.value = describe(event.state)
            }
            is AppEvent.CallStateChanged -> {
                // Use the event's authoritative `state`, NOT info.state: the core
                // emits the termination event with a CallInfo snapshot still
                // marked Connected, so keying off info.state leaves the call on
                // screen after a remote BYE.
                if (event.state == CallState.TERMINATED) {
                    if (_activeCall.value?.id == event.info.id) _activeCall.value = null
                } else {
                    _activeCall.value = event.info
                    _isMuted.value = event.info.isMuted
                    _isOnHold.value = event.info.isOnHold
                }
                val ringing = _incomingCall.value
                if (ringing != null && ringing.id == event.info.id &&
                    event.state != CallState.RINGING
                ) {
                    _incomingCall.value = null
                }
            }
            is AppEvent.IncomingCall ->
                _incomingCall.value = RingingCall(event.callId, event.remoteUri, event.remoteDisplayName)
            is AppEvent.IncomingCallCancelled ->
                if (_incomingCall.value?.id == event.callId) _incomingCall.value = null
            is AppEvent.CallEnded -> {
                if (_activeCall.value?.id == event.callId || _activeCall.value == null) {
                    _activeCall.value = null
                }
                if (_incomingCall.value?.id == event.callId) _incomingCall.value = null
                _isMuted.value = false
                _isOnHold.value = false
                refreshRecents()
            }
            is AppEvent.Error -> _errorMessage.value = event.message
            is AppEvent.ContactsChanged -> {
                refreshContacts(); refreshRecents()
            }
            is AppEvent.SettingsChanged -> {
                refreshAccount(); refreshAudio()
            }
            else -> Unit // PinRequired/PinCompleted/TransferProgress/DtmfReceived: no UI yet
        }
    }
    // endregion

    override fun onCleared() {
        super.onCleared()
        // Best-effort graceful shutdown (BYE/REGISTER expires=0) off the main thread.
        val c = client
        client = null
        if (c != null) {
            Thread {
                runCatching { c.shutdown() }
                runCatching { c.close() }
            }.start()
        }
    }

    /** Rust pushes events on a runtime worker thread; hop to main. */
    private inner class Listener : EventListener {
        override fun onEvent(event: AppEvent) {
            Log.d(TAG, "event: $event")
            viewModelScope.launch(Dispatchers.Main) { handle(event) }
        }
    }

    companion object {
        private const val TAG = "UsgSipClient"

        fun describe(state: RegistrationState): String = when (state) {
            RegistrationState.UNREGISTERED -> "Unregistered"
            RegistrationState.WAITING_FOR_PIN -> "Waiting for PIN"
            RegistrationState.REGISTERING -> "Registering…"
            RegistrationState.REGISTERED -> "Registered"
            RegistrationState.REFRESH_PENDING -> "Refreshing…"
            RegistrationState.FAILED -> "Registration failed"
            RegistrationState.SMART_CARD_NOT_PRESENT -> "Smart card not present"
            RegistrationState.CERTIFICATE_INVALID -> "Certificate invalid"
        }
    }
}
