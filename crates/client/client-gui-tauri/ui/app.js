// USG SIP Soft Client - Frontend Application Logic
// Security hardened version

// ============================================================================
// Security Constants and Utilities
// ============================================================================

// Input length limits
const MAX_DIAL_LENGTH = 30;
const MAX_CONTACT_NAME = 100;
const MAX_URI_LENGTH = 256;
const MAX_SEARCH_LENGTH = 100;

// ============================================================================
// Ringback Tone Generator
// ============================================================================

class RingbackTone {
    constructor() {
        this.audioContext = null;
        this.oscillator = null;
        this.gainNode = null;
        this.isPlaying = false;
        this.ringInterval = null;
    }

    start() {
        if (this.isPlaying) return;

        try {
            // Create audio context if needed
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }

            this.isPlaying = true;

            // Play ring pattern: 2 seconds on, 4 seconds off (US ringback)
            this.playRing();
            this.ringInterval = setInterval(() => {
                this.playRing();
            }, 6000); // Total cycle: 2s ring + 4s silence
        } catch (error) {
            console.error('Failed to start ringback tone:', error);
        }
    }

    playRing() {
        if (!this.audioContext) return;

        // Create oscillator for 440 Hz + 480 Hz (US ringback tone)
        const osc1 = this.audioContext.createOscillator();
        const osc2 = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        osc1.frequency.value = 440; // A4 note
        osc2.frequency.value = 480; // Slightly sharp
        osc1.type = 'sine';
        osc2.type = 'sine';

        // Connect oscillators to gain
        osc1.connect(gainNode);
        osc2.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        // Set volume (quieter than full volume)
        gainNode.gain.value = 0.1;

        // Start playing
        const now = this.audioContext.currentTime;
        osc1.start(now);
        osc2.start(now);

        // Stop after 2 seconds
        osc1.stop(now + 2.0);
        osc2.stop(now + 2.0);
    }

    stop() {
        if (!this.isPlaying) return;

        this.isPlaying = false;

        if (this.ringInterval) {
            clearInterval(this.ringInterval);
            this.ringInterval = null;
        }

        // Clean up audio context
        if (this.audioContext) {
            this.audioContext.close();
            this.audioContext = null;
        }
    }
}

// Global ringback tone instance
const ringbackTone = new RingbackTone();

class IncomingRingtone {
    constructor() {
        this.audioContext = null;
        this.isPlaying = false;
        this.ringInterval = null;
    }

    start() {
        if (this.isPlaying) return;

        try {
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }

            this.isPlaying = true;

            // Play ring pattern: 1 second on, 3 seconds off
            this.playRing();
            this.ringInterval = setInterval(() => {
                this.playRing();
            }, 4000);
        } catch (error) {
            console.error('Failed to start incoming ringtone:', error);
        }
    }

    playRing() {
        if (!this.audioContext) return;

        const osc1 = this.audioContext.createOscillator();
        const osc2 = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        osc1.frequency.value = 440;
        osc2.frequency.value = 480;
        osc1.type = 'sine';
        osc2.type = 'sine';

        osc1.connect(gainNode);
        osc2.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        gainNode.gain.value = 0.15;

        const now = this.audioContext.currentTime;
        osc1.start(now);
        osc2.start(now);

        osc1.stop(now + 1.0);
        osc2.stop(now + 1.0);
    }

    stop() {
        if (!this.isPlaying) return;

        this.isPlaying = false;

        if (this.ringInterval) {
            clearInterval(this.ringInterval);
            this.ringInterval = null;
        }

        if (this.audioContext) {
            this.audioContext.close();
            this.audioContext = null;
        }
    }
}

// Global incoming ringtone instance
const incomingRingtone = new IncomingRingtone();

// Rate limiting for backend calls
const rateLimiter = {
    lastCall: {},
    minInterval: 100, // ms between calls to same command

    canCall(command) {
        const now = Date.now();
        if (now - (this.lastCall[command] || 0) < this.minInterval) {
            console.warn(`Rate limited: ${command}`);
            return false;
        }
        this.lastCall[command] = now;
        return true;
    }
};

// Generate cryptographically random ID
function generateSecureId() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// Sanitize alert messages to prevent confusion attacks
function safeAlert(message) {
    const clean = String(message).replace(/<[^>]*>/g, '').slice(0, 500);
    alert(clean);
}

// Use Tauri 2.0 invoke API - access lazily to ensure Tauri is loaded
function getTauriApi() {
    // Tauri 2.0 uses __TAURI_INTERNALS__ for the core API
    if (window.__TAURI_INTERNALS__) {
        return {
            invoke: window.__TAURI_INTERNALS__.invoke,
            // For events, Tauri 2.0 uses a different approach
            listen: async (event, handler) => {
                // Use the Tauri 2.0 event API if available
                if (window.__TAURI__ && window.__TAURI__.event) {
                    return window.__TAURI__.event.listen(event, handler);
                }
                // Fallback: return noop
                return () => {};
            }
        };
    }
    // Also check for the older API path (Tauri 1.x style)
    if (window.__TAURI__) {
        return {
            invoke: window.__TAURI__.core ? window.__TAURI__.core.invoke : window.__TAURI__.invoke,
            listen: window.__TAURI__.event ? window.__TAURI__.event.listen : async () => () => {}
        };
    }
    // Fallback for development/testing
    console.warn('Tauri API not available');
    return {
        invoke: async (cmd, args) => { console.log('invoke:', cmd, args); return null; },
        listen: async (event, handler) => { console.log('listen:', event); return () => {}; }
    };
}

// Lazy getters
const invoke = (...args) => getTauriApi().invoke(...args);
const listen = (...args) => getTauriApi().listen(...args);

// Application State
let currentTab = 'dialer';
let contacts = [];
let callActive = false;
let callDurationInterval = null;
let callStartTime = null;
let isMuted = false;
let isOnHold = false;
let registrationState = 'unregistered';
let incomingCallId = null;
let currentClassification = 'unclassified';

// ============================================================================
// DTMF Tone Generator
// ============================================================================

// DTMF frequency pairs (low frequency, high frequency)
const DTMF_FREQUENCIES = {
    '1': [697, 1209], '2': [697, 1336], '3': [697, 1477], 'A': [697, 1633],
    '4': [770, 1209], '5': [770, 1336], '6': [770, 1477], 'B': [770, 1633],
    '7': [852, 1209], '8': [852, 1336], '9': [852, 1477], 'C': [852, 1633],
    '*': [941, 1209], '0': [941, 1336], '#': [941, 1477], 'D': [941, 1633]
};

// Audio context for DTMF tones (lazy initialization)
let audioContext = null;
let dtmfGainNode = null;

// Initialize audio context on first user interaction
function initAudioContext() {
    if (!audioContext) {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
        dtmfGainNode = audioContext.createGain();
        dtmfGainNode.gain.value = 0.15; // Moderate volume
        dtmfGainNode.connect(audioContext.destination);
    }
    // Resume if suspended (browsers require user interaction)
    if (audioContext.state === 'suspended') {
        audioContext.resume();
    }
    return audioContext;
}

// Play a DTMF tone for a digit
function playDtmfTone(digit, duration = 150) {
    const frequencies = DTMF_FREQUENCIES[digit];
    if (!frequencies) return;

    try {
        const ctx = initAudioContext();
        const now = ctx.currentTime;
        const endTime = now + duration / 1000;

        // Create oscillators for low and high frequencies
        const osc1 = ctx.createOscillator();
        const osc2 = ctx.createOscillator();

        osc1.type = 'sine';
        osc2.type = 'sine';
        osc1.frequency.value = frequencies[0];
        osc2.frequency.value = frequencies[1];

        // Create individual gain nodes for mixing
        const gain1 = ctx.createGain();
        const gain2 = ctx.createGain();
        gain1.gain.value = 0.5;
        gain2.gain.value = 0.5;

        // Connect: oscillators -> gains -> master gain -> destination
        osc1.connect(gain1);
        osc2.connect(gain2);
        gain1.connect(dtmfGainNode);
        gain2.connect(dtmfGainNode);

        // Start and stop
        osc1.start(now);
        osc2.start(now);
        osc1.stop(endTime);
        osc2.stop(endTime);

        // Clean up after tone ends
        osc1.onended = () => {
            osc1.disconnect();
            gain1.disconnect();
        };
        osc2.onended = () => {
            osc2.disconnect();
            gain2.disconnect();
        };
    } catch (e) {
        console.warn('Could not play DTMF tone:', e);
    }
}

// Classification levels configuration
const CLASSIFICATION_LEVELS = {
    'unclassified': { label: 'UNCLASSIFIED', color: '#007A33', textColor: '#FFFFFF' },
    'cui': { label: 'CUI', color: '#502B85', textColor: '#FFFFFF' },
    'confidential': { label: 'CONFIDENTIAL', color: '#0033A0', textColor: '#FFFFFF' },
    'secret': { label: 'SECRET', color: '#C8102E', textColor: '#FFFFFF' },
    'top-secret': { label: 'TOP SECRET', color: '#FF8C00', textColor: '#000000' },
    'top-secret-sci': { label: 'TOP SECRET//SCI', color: '#FFE11A', textColor: '#000000' }
};

// SCI Caveats and dissemination options
let classificationCaveats = [];
let classificationDissem = [];

// Common SCI caveats
const SCI_CAVEATS = ['SI', 'TK', 'G', 'HCS', 'GAMMA', 'TALENT KEYHOLE', 'COMINT'];
// Common dissemination controls
const DISSEM_CONTROLS = ['NOFORN', 'RELTO', 'ORCON', 'IMCON', 'PROPIN', 'FISA', 'FOUO'];

// Build the full classification string
function buildClassificationString() {
    const config = CLASSIFICATION_LEVELS[currentClassification];
    let label = config.label;

    // Add caveats for SCI
    if (currentClassification === 'top-secret-sci' && classificationCaveats.length > 0) {
        label = `TOP SECRET//${classificationCaveats.join('/')}`;
    }

    // Add dissemination markings
    if (classificationDissem.length > 0) {
        label += '//' + classificationDissem.join('/');
    }

    return label;
}

// Set classification level (U, C, S, TS, SCI)
function setClassification(level, caveats = [], dissem = []) {
    const normalizedLevel = level.toLowerCase().replace(/[^a-z-]/g, '');

    // Map shorthand to full classification names
    const levelMap = {
        'u': 'unclassified',
        'unclassified': 'unclassified',
        'cui': 'cui',
        'c': 'confidential',
        'confidential': 'confidential',
        's': 'secret',
        'secret': 'secret',
        'ts': 'top-secret',
        'topsecret': 'top-secret',
        'top-secret': 'top-secret',
        'sci': 'top-secret-sci',
        'tssci': 'top-secret-sci',
        'topsecretsci': 'top-secret-sci',
        'top-secret-sci': 'top-secret-sci'
    };

    const classLevel = levelMap[normalizedLevel] || 'unclassified';
    currentClassification = classLevel;

    // Validate caveats and dissemination controls against whitelists
    classificationCaveats = Array.isArray(caveats)
        ? caveats.filter(c => SCI_CAVEATS.includes(c))
        : [];
    classificationDissem = Array.isArray(dissem)
        ? dissem.filter(d => DISSEM_CONTROLS.includes(d))
        : [];

    updateClassificationBars();

    // Store in localStorage for persistence
    saveClassificationConfig();

    console.log('Classification set to:', buildClassificationString());
}

// Update classification bars display
function updateClassificationBars() {
    const config = CLASSIFICATION_LEVELS[currentClassification];
    const label = buildClassificationString();
    const bars = document.querySelectorAll('.classification-bar');

    bars.forEach(bar => {
        // Set classification level as data attribute for CSS styling
        bar.dataset.classification = currentClassification;
        const textEl = bar.querySelector('.classification-text');
        if (textEl) {
            textEl.textContent = label;
        }
    });
}

// Save classification config (only via Tauri backend - no localStorage for security)
function saveClassificationConfig() {
    const config = {
        level: currentClassification,
        caveats: classificationCaveats,
        dissem: classificationDissem
    };

    // Save via Tauri invoke only (no localStorage for sensitive data)
    try {
        invoke('save_classification_config', { config }).catch(() => {});
    } catch (e) {
        // Ignore if command not available
    }
}

// Load classification from storage on init
async function loadClassification() {
    // Load from Tauri backend (persistent config file)
    try {
        const config = await invoke('get_classification_config');
        if (config && config.level) {
            currentClassification = config.level;
            classificationCaveats = config.caveats || [];
            classificationDissem = config.dissem || [];
            updateClassificationBars();
            console.log('Loaded classification from config file:', buildClassificationString());
            return;
        }
    } catch (e) {
        console.warn('Could not load classification from Tauri backend:', e);
    }

    // Default to unclassified
    currentClassification = 'unclassified';
    classificationCaveats = [];
    classificationDissem = [];
    updateClassificationBars();
}


// Initialize the application
document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOMContentLoaded fired - starting initialization');

    // Load classification level from storage (async - loads from config file)
    await loadClassification();

    // Debug layout
    console.log('=== Layout Debug ===');
    const topBar = document.querySelector('.classification-bar-top');
    const bottomBar = document.querySelector('.classification-bar-bottom');
    const appContainer = document.querySelector('.app-container');
    const body = document.body;

    if (topBar) console.log('Top bar:', topBar.offsetHeight, 'px', getComputedStyle(topBar).display);
    if (bottomBar) console.log('Bottom bar:', bottomBar.offsetHeight, 'px', getComputedStyle(bottomBar).display);
    if (appContainer) console.log('App container:', appContainer.offsetHeight, 'px', getComputedStyle(appContainer).flex);
    console.log('Body:', body.offsetHeight, 'px', 'Window:', window.innerHeight, 'px');
    console.log('===================');

    console.log('Initializing tabs...');
    initializeTabs();
    console.log('Initializing dialer...');
    initializeDialer();
    console.log('Initializing contacts...');
    initializeContacts();
    console.log('Initializing favorites...');
    initializeFavorites();
    console.log('Initializing recents...');
    initializeRecents();
    console.log('Initializing call...');
    initializeCall();
    console.log('Initializing settings...');
    initializeSettings();
    console.log('Initializing event listeners...');
    await initializeEventListeners();
    console.log('Event listeners initialized');
    console.log('All UI initialization complete');

    // Initialize the SIP client core
    try {
        await invoke('initialize_client');
        console.log('SIP client initialized');
    } catch (error) {
        console.error('Failed to initialize client:', error);
    }

    await loadContacts();
    await loadAudioDevices();
    await updateRegistrationStatus();

    // Initialize certificates
    await initializeCertificates();

    // Check if digest auth feature is enabled and show/hide UI accordingly
    await initializeDigestAuth();
});

// Initialize digest auth UI based on feature flag
async function initializeDigestAuth() {
    try {
        const digestAuthEnabled = await invoke('is_digest_auth_enabled');
        const digestAuthSection = document.getElementById('digestAuthSection');
        if (digestAuthSection) {
            if (digestAuthEnabled) {
                digestAuthSection.classList.remove('hidden');
                digestAuthSection.classList.add('visible-block');
            } else {
                digestAuthSection.classList.add('hidden');
                digestAuthSection.classList.remove('visible-block');
            }
        }
        if (digestAuthEnabled) {
            console.log('Digest auth feature enabled - testing mode available');
        }
    } catch (error) {
        console.log('Digest auth check skipped:', error);
    }
}

// Event Listeners for backend events
async function initializeEventListeners() {
    // Registration state changes
    await listen('registration-state-changed', (event) => {
        console.log('Registration state changed:', event.payload);
        registrationState = event.payload.state.toLowerCase();
        updateStatus(registrationState === 'registered' ? 'online' : 'offline');
    });

    // Call state changes
    await listen('call-state-changed', (event) => {
        console.log('Call state changed:', event.payload);
        handleCallStateChange(event.payload);
    });

    // Incoming call
    await listen('incoming-call', (event) => {
        console.log('Incoming call:', event.payload);
        handleIncomingCall(event.payload);
    });

    // Incoming call cancelled by remote party
    await listen('incoming-call-cancelled', (event) => {
        console.log('Incoming call cancelled:', event.payload);
        dismissIncomingCallModal();
    });

    // Call ended
    await listen('call-ended', (event) => {
        console.log('Call ended:', event.payload);
        endCall();
    });

    // Error events
    await listen('error', (event) => {
        console.error('Error:', event.payload);
        safeAlert(event.payload.message || 'An error occurred');
    });

    // Transfer progress
    await listen('transfer-progress', (event) => {
        console.log('Transfer progress:', event.payload);
        handleTransferProgress(event.payload);
    });
}

function handleCallStateChange(payload) {
    const { call_id, state, remote_uri, remote_display_name } = payload;

    if (state === 'Ringing' || state === 'ringing') {
        // Play ringback tone while waiting for answer
        ringbackTone.start();
    } else if (state === 'Connected' || state === 'connected') {
        // Stop ringback tone when call is answered
        ringbackTone.stop();
        if (!callActive) {
            startCall(remote_display_name || remote_uri);
        }
        isOnHold = false;
        updateHoldButton();
    } else if (state === 'Terminated' || state === 'terminated') {
        // Stop ringback tone when call ends
        ringbackTone.stop();
        endCall();
    } else if (state === 'OnHold' || state === 'on_hold') {
        isOnHold = true;
        updateHoldButton();
    }
}

function handleIncomingCall(payload) {
    const { call_id, remote_uri, remote_display_name } = payload;
    incomingCallId = call_id;

    // Sanitize caller info for display
    const callerName = escapeHtml(remote_display_name || 'Unknown').slice(0, 100);
    const callerUri = escapeHtml(remote_uri || '').slice(0, 256);

    document.getElementById('incomingCallerName').textContent = callerName;
    document.getElementById('incomingCallerUri').textContent = callerUri;
    document.getElementById('incomingCallModal').classList.add('active');

    incomingRingtone.start();
}

function dismissIncomingCallModal() {
    document.getElementById('incomingCallModal').classList.remove('active');
    incomingRingtone.stop();
    incomingCallId = null;
}

async function acceptIncomingCall(callId) {
    dismissIncomingCallModal();
    if (!rateLimiter.canCall('accept_call')) return;
    try {
        await invoke('accept_call', { callId });
    } catch (error) {
        console.error('Failed to accept call:', error);
        safeAlert('Failed to accept call');
    }
}

async function rejectIncomingCall(callId) {
    dismissIncomingCallModal();
    try {
        await invoke('reject_call', { callId });
    } catch (error) {
        console.error('Failed to reject call:', error);
    }
}

function handleTransferProgress(payload) {
    const { status_code, is_success, is_final } = payload;

    if (is_final) {
        if (is_success) {
            alert('Call transferred successfully');
            endCall();
        } else {
            alert(`Transfer failed (${status_code})`);
        }
    }
}

// Tab Management
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === tabName);
    });

    currentTab = tabName;
}

// Country code database with formatting patterns
// Format: { cc: [length, pattern] } where pattern uses X for digits, spaces for grouping
// Patterns based on ITU-T E.164 and local conventions
const COUNTRY_FORMATS = {
    // 1-digit country codes
    '1':   { len: 1, name: 'NANP', pattern: '(XXX) XXX-XXXX' },           // USA, Canada, Caribbean
    '7':   { len: 1, name: 'Russia/Kazakhstan', pattern: 'XXX XXX-XX-XX' },

    // 2-digit country codes (2X)
    '20':  { len: 2, name: 'Egypt', pattern: 'XX XXXX XXXX' },
    '27':  { len: 2, name: 'South Africa', pattern: 'XX XXX XXXX' },

    // 2-digit country codes (3X)
    '30':  { len: 2, name: 'Greece', pattern: 'XXX XXX XXXX' },
    '31':  { len: 2, name: 'Netherlands', pattern: 'X XX XX XX XX' },
    '32':  { len: 2, name: 'Belgium', pattern: 'XXX XX XX XX' },
    '33':  { len: 2, name: 'France', pattern: 'X XX XX XX XX' },
    '34':  { len: 2, name: 'Spain', pattern: 'XXX XXX XXX' },
    '36':  { len: 2, name: 'Hungary', pattern: 'XX XXX XXXX' },
    '39':  { len: 2, name: 'Italy', pattern: 'XXX XXX XXXX' },

    // 2-digit country codes (4X)
    '40':  { len: 2, name: 'Romania', pattern: 'XXX XXX XXX' },
    '41':  { len: 2, name: 'Switzerland', pattern: 'XX XXX XX XX' },
    '43':  { len: 2, name: 'Austria', pattern: 'XXX XXXXXX' },
    '44':  { len: 2, name: 'UK', pattern: 'XXXX XXXXXX' },
    '45':  { len: 2, name: 'Denmark', pattern: 'XX XX XX XX' },
    '46':  { len: 2, name: 'Sweden', pattern: 'XX XXX XX XX' },
    '47':  { len: 2, name: 'Norway', pattern: 'XXX XX XXX' },
    '48':  { len: 2, name: 'Poland', pattern: 'XXX XXX XXX' },
    '49':  { len: 2, name: 'Germany', pattern: 'XXXX XXXXXXX' },

    // 2-digit country codes (5X)
    '51':  { len: 2, name: 'Peru', pattern: 'XXX XXX XXX' },
    '52':  { len: 2, name: 'Mexico', pattern: 'XX XXXX XXXX' },
    '53':  { len: 2, name: 'Cuba', pattern: 'X XXX XXXX' },
    '54':  { len: 2, name: 'Argentina', pattern: 'XX XXXX-XXXX' },
    '55':  { len: 2, name: 'Brazil', pattern: 'XX XXXXX-XXXX' },
    '56':  { len: 2, name: 'Chile', pattern: 'X XXXX XXXX' },
    '57':  { len: 2, name: 'Colombia', pattern: 'XXX XXX XXXX' },
    '58':  { len: 2, name: 'Venezuela', pattern: 'XXX XXX XXXX' },

    // 2-digit country codes (6X)
    '60':  { len: 2, name: 'Malaysia', pattern: 'XX XXXX XXXX' },
    '61':  { len: 2, name: 'Australia', pattern: 'XXX XXX XXX' },
    '62':  { len: 2, name: 'Indonesia', pattern: 'XXX XXXX XXXX' },
    '63':  { len: 2, name: 'Philippines', pattern: 'XXX XXX XXXX' },
    '64':  { len: 2, name: 'New Zealand', pattern: 'XX XXX XXXX' },
    '65':  { len: 2, name: 'Singapore', pattern: 'XXXX XXXX' },
    '66':  { len: 2, name: 'Thailand', pattern: 'XX XXX XXXX' },

    // 2-digit country codes (8X)
    '81':  { len: 2, name: 'Japan', pattern: 'XX XXXX XXXX' },
    '82':  { len: 2, name: 'South Korea', pattern: 'XX XXXX XXXX' },
    '84':  { len: 2, name: 'Vietnam', pattern: 'XXX XXX XXXX' },
    '86':  { len: 2, name: 'China', pattern: 'XXX XXXX XXXX' },

    // 2-digit country codes (9X)
    '90':  { len: 2, name: 'Turkey', pattern: 'XXX XXX XX XX' },
    '91':  { len: 2, name: 'India', pattern: 'XXXXX XXXXX' },
    '92':  { len: 2, name: 'Pakistan', pattern: 'XXX XXXXXXX' },
    '93':  { len: 2, name: 'Afghanistan', pattern: 'XX XXX XXXX' },
    '94':  { len: 2, name: 'Sri Lanka', pattern: 'XX XXX XXXX' },
    '95':  { len: 2, name: 'Myanmar', pattern: 'XX XXX XXXX' },
    '98':  { len: 2, name: 'Iran', pattern: 'XXX XXX XXXX' },

    // 3-digit country codes (2XX)
    '211': { len: 3, name: 'South Sudan', pattern: 'XXX XXX XXX' },
    '212': { len: 3, name: 'Morocco', pattern: 'XXX XXXXXX' },
    '213': { len: 3, name: 'Algeria', pattern: 'XXX XX XX XX' },
    '216': { len: 3, name: 'Tunisia', pattern: 'XX XXX XXX' },
    '218': { len: 3, name: 'Libya', pattern: 'XX XXX XXXX' },
    '220': { len: 3, name: 'Gambia', pattern: 'XXX XXXX' },
    '221': { len: 3, name: 'Senegal', pattern: 'XX XXX XX XX' },
    '234': { len: 3, name: 'Nigeria', pattern: 'XXX XXX XXXX' },
    '249': { len: 3, name: 'Sudan', pattern: 'XX XXX XXXX' },
    '250': { len: 3, name: 'Rwanda', pattern: 'XXX XXX XXX' },
    '251': { len: 3, name: 'Ethiopia', pattern: 'XX XXX XXXX' },
    '254': { len: 3, name: 'Kenya', pattern: 'XXX XXXXXX' },
    '255': { len: 3, name: 'Tanzania', pattern: 'XXX XXX XXX' },
    '256': { len: 3, name: 'Uganda', pattern: 'XXX XXXXXX' },
    '260': { len: 3, name: 'Zambia', pattern: 'XX XXX XXXX' },
    '263': { len: 3, name: 'Zimbabwe', pattern: 'XX XXX XXXX' },

    // 3-digit country codes (3XX)
    '351': { len: 3, name: 'Portugal', pattern: 'XXX XXX XXX' },
    '352': { len: 3, name: 'Luxembourg', pattern: 'XXX XXX XXX' },
    '353': { len: 3, name: 'Ireland', pattern: 'XX XXX XXXX' },
    '354': { len: 3, name: 'Iceland', pattern: 'XXX XXXX' },
    '355': { len: 3, name: 'Albania', pattern: 'XX XXX XXXX' },
    '356': { len: 3, name: 'Malta', pattern: 'XXXX XXXX' },
    '357': { len: 3, name: 'Cyprus', pattern: 'XX XXXXXX' },
    '358': { len: 3, name: 'Finland', pattern: 'XX XXX XXXX' },
    '359': { len: 3, name: 'Bulgaria', pattern: 'XXX XXX XXX' },
    '370': { len: 3, name: 'Lithuania', pattern: 'XXX XXXXX' },
    '371': { len: 3, name: 'Latvia', pattern: 'XXXX XXXX' },
    '372': { len: 3, name: 'Estonia', pattern: 'XXXX XXXX' },
    '373': { len: 3, name: 'Moldova', pattern: 'XXXX XXXX' },
    '374': { len: 3, name: 'Armenia', pattern: 'XX XXXXXX' },
    '375': { len: 3, name: 'Belarus', pattern: 'XX XXX XX XX' },
    '380': { len: 3, name: 'Ukraine', pattern: 'XX XXX XX XX' },
    '381': { len: 3, name: 'Serbia', pattern: 'XX XXX XXXX' },
    '385': { len: 3, name: 'Croatia', pattern: 'XX XXX XXXX' },
    '386': { len: 3, name: 'Slovenia', pattern: 'XX XXX XXX' },
    '387': { len: 3, name: 'Bosnia', pattern: 'XX XXX XXX' },

    // 3-digit country codes (4XX)
    '420': { len: 3, name: 'Czech Republic', pattern: 'XXX XXX XXX' },
    '421': { len: 3, name: 'Slovakia', pattern: 'XXX XXX XXX' },

    // 3-digit country codes (8XX)
    '852': { len: 3, name: 'Hong Kong', pattern: 'XXXX XXXX' },
    '853': { len: 3, name: 'Macau', pattern: 'XXXX XXXX' },
    '855': { len: 3, name: 'Cambodia', pattern: 'XX XXX XXXX' },
    '856': { len: 3, name: 'Laos', pattern: 'XX XX XXX XXX' },

    // 3-digit country codes (9XX)
    '960': { len: 3, name: 'Maldives', pattern: 'XXX XXXX' },
    '961': { len: 3, name: 'Lebanon', pattern: 'XX XXX XXX' },
    '962': { len: 3, name: 'Jordan', pattern: 'X XXXX XXXX' },
    '963': { len: 3, name: 'Syria', pattern: 'XXX XXX XXX' },
    '964': { len: 3, name: 'Iraq', pattern: 'XXX XXX XXXX' },
    '965': { len: 3, name: 'Kuwait', pattern: 'XXXX XXXX' },
    '966': { len: 3, name: 'Saudi Arabia', pattern: 'XX XXX XXXX' },
    '967': { len: 3, name: 'Yemen', pattern: 'XXX XXX XXX' },
    '968': { len: 3, name: 'Oman', pattern: 'XXXX XXXX' },
    '970': { len: 3, name: 'Palestine', pattern: 'XXX XX XXXX' },
    '971': { len: 3, name: 'UAE', pattern: 'XX XXX XXXX' },
    '972': { len: 3, name: 'Israel', pattern: 'XX XXX XXXX' },
    '973': { len: 3, name: 'Bahrain', pattern: 'XXXX XXXX' },
    '974': { len: 3, name: 'Qatar', pattern: 'XXXX XXXX' },
    '975': { len: 3, name: 'Bhutan', pattern: 'XX XX XX XX' },
    '976': { len: 3, name: 'Mongolia', pattern: 'XXXX XXXX' },
    '977': { len: 3, name: 'Nepal', pattern: 'XXX XXX XXXX' },
    '992': { len: 3, name: 'Tajikistan', pattern: 'XX XXX XXXX' },
    '993': { len: 3, name: 'Turkmenistan', pattern: 'XX XXXXXX' },
    '994': { len: 3, name: 'Azerbaijan', pattern: 'XX XXX XX XX' },
    '995': { len: 3, name: 'Georgia', pattern: 'XXX XX XX XX' },
    '996': { len: 3, name: 'Kyrgyzstan', pattern: 'XXX XXXXXX' },
    '998': { len: 3, name: 'Uzbekistan', pattern: 'XX XXX XX XX' },
};

// Phone number formatting with international support
// Detects NANP (North American) vs international numbers
function formatPhoneNumber(value, forceInternational = false) {
    // If it looks like a SIP URI, don't format
    if (value.includes('@') || value.startsWith('sip:') || value.startsWith('sips:')) {
        return value;
    }

    // Check if user explicitly typed + for international
    const startsWithPlus = value.startsWith('+');

    // Strip all non-digit characters
    const digits = value.replace(/\D/g, '');

    if (digits.length === 0) {
        return startsWithPlus ? '+' : '';
    }

    // International mode: starts with + OR forced
    const isInternational = startsWithPlus || forceInternational ||
        (digits.length > 10 && digits[0] !== '1');

    if (isInternational) {
        return formatInternational(digits);
    } else {
        return formatNANP(digits);
    }
}

// Format as NANP: (555) 123-4567 or +1 (555) 123-4567
function formatNANP(digits) {
    // If starts with 1, treat as country code
    if (digits.length > 10 && digits[0] === '1') {
        const national = digits.slice(1);
        if (national.length <= 10) {
            return `+1 ${formatNANPNational(national)}`;
        }
    }

    return formatNANPNational(digits);
}

// Format national NANP number (without country code)
function formatNANPNational(digits) {
    // Only show full NANP format (with parentheses) when we have 8+ digits
    // This indicates an area code + at least 4 digits of a 7-digit local number
    if (digits.length < 8) {
        // Before 8 digits, just show the raw digits with a dash after 3
        if (digits.length <= 3) {
            return digits;
        } else if (digits.length <= 7) {
            return `${digits.slice(0, 3)}-${digits.slice(3)}`;
        }
    }

    // 8+ digits: show full NANP format with area code in parentheses
    return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6, 10)}`;
}

// Get country info from digits
function getCountryInfo(digits) {
    // Try 3-digit, then 2-digit, then 1-digit country codes
    for (const len of [3, 2, 1]) {
        if (digits.length >= len) {
            const cc = digits.slice(0, len);
            if (COUNTRY_FORMATS[cc]) {
                return { code: cc, ...COUNTRY_FORMATS[cc] };
            }
        }
    }

    // Default fallback
    return { code: digits.slice(0, 2), len: 2, name: 'Unknown', pattern: 'XXX XXX XXXX' };
}

// Apply a pattern to digits
function applyPattern(pattern, digits) {
    let result = '';
    let digitIndex = 0;

    for (const char of pattern) {
        if (digitIndex >= digits.length) break;

        if (char === 'X') {
            result += digits[digitIndex];
            digitIndex++;
        } else {
            result += char;
        }
    }

    // Append any remaining digits
    if (digitIndex < digits.length) {
        if (result.length > 0 && !result.endsWith(' ') && !result.endsWith('-')) {
            result += ' ';
        }
        result += digits.slice(digitIndex);
    }

    return result;
}

// Format international number based on country code
function formatInternational(digits) {
    if (digits.length === 0) {
        return '+';
    }

    const country = getCountryInfo(digits);
    const cc = digits.slice(0, country.len);
    const national = digits.slice(country.len);

    if (national.length === 0) {
        return `+${cc}`;
    }

    // Special case for NANP (+1)
    if (cc === '1') {
        return `+1 ${formatNANPNational(national)}`;
    }

    // Apply the country's pattern
    const formatted = applyPattern(country.pattern, national);

    return `+${cc} ${formatted}`;
}

// Extract raw digits from formatted number for dialing
// Preserves + prefix for international numbers
function extractDigits(value) {
    // If it's a SIP URI, return as-is
    if (value.includes('@') || value.startsWith('sip:') || value.startsWith('sips:')) {
        return value;
    }
    const digits = value.replace(/\D/g, '');
    // Preserve + for international format
    if (value.startsWith('+') && digits.length > 0) {
        return '+' + digits;
    }
    return digits;
}

// Track if user is in international mode (typed +)
let internationalMode = false;

// Update dial input font size based on content length
function updateDialInputSize(input) {
    if (!input) return;

    const length = input.value.length;

    // Remove all size classes
    input.classList.remove('size-xl', 'size-lg', 'size-md', 'size-sm', 'size-xs');

    // Apply appropriate size class based on character count
    if (length <= 8) {
        input.classList.add('size-xl');
    } else if (length <= 12) {
        input.classList.add('size-lg');
    } else if (length <= 16) {
        input.classList.add('size-md');
    } else if (length <= 20) {
        input.classList.add('size-sm');
    } else {
        input.classList.add('size-xs');
    }
}

// Dialer Functions
function initializeDialer() {
    const dialInput = document.getElementById('dialInput');
    const dialpadBtns = document.querySelectorAll('.dialpad-btn');
    const backspaceBtn = document.getElementById('backspaceBtn');
    const callBtn = document.getElementById('callBtn');

    // Long-press timer for 0 -> +
    let longPressTimer = null;
    const LONG_PRESS_DURATION = 500; // ms

    dialpadBtns.forEach(btn => {
        const digit = btn.dataset.digit;

        // Handle long-press on 0 for +
        if (digit === '0') {
            btn.addEventListener('mousedown', () => {
                longPressTimer = setTimeout(() => {
                    internationalMode = true;
                    const currentDigits = dialInput.value.replace(/\D/g, '');
                    dialInput.value = formatPhoneNumber('+' + currentDigits, true);
                    updateDialInputSize(dialInput);
                    longPressTimer = null; // Mark as handled
                }, LONG_PRESS_DURATION);
            });

            btn.addEventListener('mouseup', () => {
                if (longPressTimer !== null) {
                    // Short press - add 0
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                    playDtmfTone('0');
                    const currentDigits = dialInput.value.replace(/\D/g, '');
                    dialInput.value = formatPhoneNumber(
                        (internationalMode ? '+' : '') + currentDigits + '0',
                        internationalMode
                    );
                    updateDialInputSize(dialInput);
                }
            });

            btn.addEventListener('mouseleave', () => {
                if (longPressTimer !== null) {
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                }
            });

            // Touch support
            btn.addEventListener('touchstart', (e) => {
                e.preventDefault();
                longPressTimer = setTimeout(() => {
                    internationalMode = true;
                    const currentDigits = dialInput.value.replace(/\D/g, '');
                    dialInput.value = formatPhoneNumber('+' + currentDigits, true);
                    updateDialInputSize(dialInput);
                    longPressTimer = null;
                }, LONG_PRESS_DURATION);
            });

            btn.addEventListener('touchend', (e) => {
                e.preventDefault();
                if (longPressTimer !== null) {
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                    playDtmfTone('0');
                    const currentDigits = dialInput.value.replace(/\D/g, '');
                    dialInput.value = formatPhoneNumber(
                        (internationalMode ? '+' : '') + currentDigits + '0',
                        internationalMode
                    );
                    updateDialInputSize(dialInput);
                }
            });
        } else {
            // Regular digit buttons
            btn.addEventListener('click', () => {
                playDtmfTone(digit);
                const currentDigits = dialInput.value.replace(/\D/g, '');
                dialInput.value = formatPhoneNumber(
                    (internationalMode ? '+' : '') + currentDigits + digit,
                    internationalMode
                );
                updateDialInputSize(dialInput);
            });
        }
    });

    backspaceBtn.addEventListener('click', () => {
        const currentDigits = dialInput.value.replace(/\D/g, '');
        if (currentDigits.length === 0) {
            // If we're deleting the last digit, also exit international mode
            internationalMode = false;
            dialInput.value = '';
        } else {
            dialInput.value = formatPhoneNumber(
                (internationalMode ? '+' : '') + currentDigits.slice(0, -1),
                internationalMode
            );
        }
        updateDialInputSize(dialInput);
    });

    // Auto-format on manual input with length limit and sanitization
    dialInput.addEventListener('input', (e) => {
        const cursorPos = e.target.selectionStart;
        let oldValue = e.target.value;

        // Sanitize input: allow only digits, +, @, and SIP URI characters (letters, dots, hyphens, colons)
        // For SIP URIs: sip:user@domain.com or sips:user@domain.com
        const sanitizedValue = oldValue.replace(/[^0-9+@.:a-zA-Z\-]/g, '');

        if (sanitizedValue !== oldValue) {
            // Invalid characters were removed, update the value
            oldValue = sanitizedValue;
            e.target.value = sanitizedValue;
        }

        // Enforce max length on raw digits (for phone numbers)
        const digits = oldValue.replace(/\D/g, '');
        if (digits.length > MAX_DIAL_LENGTH && !oldValue.includes('@')) {
            // Only enforce digit limit if it's not a SIP URI
            oldValue = oldValue.slice(0, -1);
            e.target.value = oldValue;
            return;
        }

        // Enforce max URI length for SIP URIs
        if (oldValue.includes('@') && oldValue.length > MAX_URI_LENGTH) {
            oldValue = oldValue.slice(0, MAX_URI_LENGTH);
            e.target.value = oldValue;
            return;
        }

        // Detect if user typed +
        if (oldValue.includes('+')) {
            internationalMode = true;
        }

        // If field is cleared, reset international mode
        if (digits.length === 0 && !oldValue.includes('+')) {
            internationalMode = false;
        }

        const newValue = formatPhoneNumber(oldValue, internationalMode);

        if (newValue !== oldValue) {
            e.target.value = newValue;
            // Try to maintain cursor position reasonably
            const diff = newValue.length - oldValue.length;
            e.target.setSelectionRange(cursorPos + diff, cursorPos + diff);
        }

        updateDialInputSize(dialInput);
    });

    // Initialize size class
    updateDialInputSize(dialInput);

    callBtn.addEventListener('click', async () => {
        console.log('Call button clicked');
        console.log('dialInput.value:', dialInput.value);
        const target = extractDigits(dialInput.value.trim());
        console.log('Extracted target:', target);
        if (target) {
            await makeCall(target);
        } else {
            console.warn('Call button clicked but no target entered');
            safeAlert('Please enter a number to call');
        }
    });

    // Handle Enter key in dial input
    dialInput.addEventListener('keypress', async (e) => {
        if (e.key === 'Enter') {
            const target = extractDigits(dialInput.value.trim());
            if (target) {
                await makeCall(target);
            }
        }
    });

    // Global keyboard handler for dialing without clicking
    document.addEventListener('keydown', async (e) => {
        // Only handle when dial tab is active or no input is focused
        const activeTab = document.querySelector('.tab-content.active');
        const isDialerActive = activeTab && activeTab.id === 'dialer';
        const activeElement = document.activeElement;
        const isInputFocused = activeElement && (
            activeElement.tagName === 'INPUT' ||
            activeElement.tagName === 'TEXTAREA' ||
            activeElement.tagName === 'SELECT'
        );

        // If we're on the dialer tab and no other input is focused (except dialInput)
        if (isDialerActive && (!isInputFocused || activeElement === dialInput)) {
            const key = e.key;

            // Handle digit keys (0-9)
            if (/^[0-9]$/.test(key)) {
                e.preventDefault();
                playDtmfTone(key);
                const currentDigits = dialInput.value.replace(/\D/g, '');
                dialInput.value = formatPhoneNumber(
                    (internationalMode ? '+' : '') + currentDigits + key,
                    internationalMode
                );
                updateDialInputSize(dialInput);
                dialInput.focus();
            }
            // Handle * and # keys
            else if (key === '*' || key === '#') {
                e.preventDefault();
                playDtmfTone(key);
                const currentDigits = dialInput.value.replace(/\D/g, '');
                dialInput.value = formatPhoneNumber(
                    (internationalMode ? '+' : '') + currentDigits + key,
                    internationalMode
                );
                updateDialInputSize(dialInput);
                dialInput.focus();
            }
            // Handle + key for international
            else if (key === '+') {
                e.preventDefault();
                internationalMode = true;
                const currentDigits = dialInput.value.replace(/\D/g, '');
                dialInput.value = formatPhoneNumber('+' + currentDigits, true);
                updateDialInputSize(dialInput);
                dialInput.focus();
            }
            // Handle Backspace
            else if (key === 'Backspace' && !isInputFocused) {
                e.preventDefault();
                const currentDigits = dialInput.value.replace(/\D/g, '');
                if (currentDigits.length === 0) {
                    internationalMode = false;
                    dialInput.value = '';
                } else {
                    dialInput.value = formatPhoneNumber(
                        (internationalMode ? '+' : '') + currentDigits.slice(0, -1),
                        internationalMode
                    );
                }
                updateDialInputSize(dialInput);
            }
            // Handle Enter to call
            else if (key === 'Enter' && !isInputFocused) {
                e.preventDefault();
                const target = extractDigits(dialInput.value.trim());
                if (target) {
                    await makeCall(target);
                }
            }
        }
    });
}

// Validates dial target for safe SIP URI characters
function isValidDialTarget(target) {
    // Whitelist approach: only allow valid SIP URI characters
    // Allow: alphanumeric, +, @, ., :, _, -, and sip/sips scheme
    const validPattern = /^(sips?:)?[a-zA-Z0-9+@.:_-]+$/;
    return validPattern.test(target) && target.length <= MAX_URI_LENGTH;
}

async function makeCall(target) {
    console.log('makeCall called with target:', target);

    if (!rateLimiter.canCall('make_call')) {
        console.warn('makeCall rate limited');
        return;
    }

    // Extract digits if formatted, preserve SIP URIs
    const dialTarget = extractDigits(target).slice(0, MAX_URI_LENGTH);
    console.log('dialTarget after extractDigits:', dialTarget);

    // Validate dial target to prevent SIP header injection
    if (!isValidDialTarget(dialTarget)) {
        console.error('Invalid dial target characters detected');
        safeAlert('Invalid dial target. Only alphanumeric characters and basic SIP URI characters are allowed.');
        return;
    }

    // Add sip: prefix if not present
    let sipUri = dialTarget;
    if (!sipUri.startsWith('sip:') && !sipUri.startsWith('sips:')) {
        sipUri = `sip:${dialTarget}`;
    }
    console.log('Final sipUri:', sipUri);

    try {
        console.log('Invoking make_call with:', sipUri);
        const result = await invoke('make_call', { target: sipUri });
        console.log('Call initiated:', result);
        startCall(target);
    } catch (error) {
        console.error('Failed to make call:', error);
        safeAlert('Failed to make call: ' + error);
    }
}

function startCall(target) {
    callActive = true;
    callStartTime = Date.now();
    isMuted = false;
    isOnHold = false;

    // Transition to call screen
    const callInfo = document.getElementById('callInfo');
    callInfo.classList.remove('hidden');
    callInfo.classList.add('visible-block', 'visible');

    const dialInputWrapper = document.getElementById('dialInputWrapper');
    dialInputWrapper.classList.add('hidden');
    dialInputWrapper.classList.remove('visible-block');

    const dialpad = document.getElementById('dialpad');
    dialpad.classList.add('hidden');
    dialpad.classList.remove('visible-grid');

    const audioDevices = document.getElementById('audioDevices');
    audioDevices.classList.add('hidden');
    audioDevices.classList.remove('visible-block');

    const callControls = document.getElementById('callControls');
    callControls.classList.remove('hidden');
    callControls.classList.add('visible-grid');

    // Show hangup button, hide call button and backspace
    const callBtn = document.getElementById('callBtn');
    callBtn.classList.add('hidden');
    callBtn.classList.remove('visible-block');

    const backspaceBtn = document.getElementById('backspaceBtn');
    backspaceBtn.classList.add('hidden');
    backspaceBtn.classList.remove('visible-block');

    const hangupBtn = document.getElementById('hangupBtn');
    hangupBtn.classList.remove('hidden');
    hangupBtn.classList.add('visible-block');

    document.getElementById('callTarget').textContent = target;

    // Show call duration
    const durationElement = document.getElementById('callDuration');
    if (durationElement) {
        durationElement.classList.add('active');
    }

    // Enable call controls
    document.getElementById('muteBtn').disabled = false;
    document.getElementById('holdBtn').disabled = false;
    document.getElementById('keypadBtn').disabled = false;
    document.getElementById('transferBtn').disabled = false;
    document.getElementById('hangupBtn').disabled = false;

    // Reset button states
    updateMuteButton();
    updateHoldButton();

    // Start duration timer
    updateCallDuration();
    callDurationInterval = setInterval(updateCallDuration, 1000);

    // Update status
    updateStatus('online');
}

function updateCallDuration() {
    if (!callStartTime) return;

    const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
    const minutes = Math.floor(elapsed / 60);
    const seconds = elapsed % 60;

    document.getElementById('callDuration').textContent =
        `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function endCall() {
    callActive = false;
    callStartTime = null;
    isMuted = false;
    isOnHold = false;
    incomingCallId = null;

    // Stop any ringing tones
    ringbackTone.stop();
    incomingRingtone.stop();
    document.getElementById('incomingCallModal').classList.remove('active');

    if (callDurationInterval) {
        clearInterval(callDurationInterval);
        callDurationInterval = null;
    }

    // Transition back to dialer screen
    const callInfo = document.getElementById('callInfo');
    callInfo.classList.remove('visible', 'visible-block');
    callInfo.classList.add('hidden');

    const dialInputWrapper = document.getElementById('dialInputWrapper');
    dialInputWrapper.classList.remove('hidden');
    dialInputWrapper.classList.add('visible-block');

    const dialpad = document.getElementById('dialpad');
    dialpad.classList.remove('hidden');
    dialpad.classList.add('visible-grid');

    const audioDevices = document.getElementById('audioDevices');
    audioDevices.classList.remove('hidden');
    audioDevices.classList.add('visible-block');

    const callControls = document.getElementById('callControls');
    callControls.classList.add('hidden');
    callControls.classList.remove('visible-grid');

    // Show call button and backspace, hide hangup button
    const callBtn = document.getElementById('callBtn');
    callBtn.classList.remove('hidden');
    callBtn.classList.add('visible-block');

    const backspaceBtn = document.getElementById('backspaceBtn');
    backspaceBtn.classList.remove('hidden');
    backspaceBtn.classList.add('visible-block');

    const hangupBtn = document.getElementById('hangupBtn');
    hangupBtn.classList.add('hidden');
    hangupBtn.classList.remove('visible-block');

    // Clear call display and dial input
    document.getElementById('callTarget').textContent = '';
    const durationElement = document.getElementById('callDuration');
    durationElement.textContent = '00:00';
    durationElement.classList.remove('active');
    const dialInput = document.getElementById('dialInput');
    if (dialInput) {
        dialInput.value = '';
    }

    // Disable call controls
    document.getElementById('muteBtn').disabled = true;
    document.getElementById('holdBtn').disabled = true;
    document.getElementById('keypadBtn').disabled = true;
    document.getElementById('transferBtn').disabled = true;
    document.getElementById('hangupBtn').disabled = true;

    // Reset button states
    updateMuteButton();
    updateHoldButton();

    // Stay on dialer tab (don't switch tabs)
    switchTab('dialer');
}

function updateMuteButton() {
    const muteBtn = document.getElementById('muteBtn');
    muteBtn.classList.toggle('active', isMuted);
    muteBtn.querySelector('.label').textContent = isMuted ? 'Unmute' : 'Mute';
}

function updateHoldButton() {
    const holdBtn = document.getElementById('holdBtn');
    holdBtn.classList.toggle('active', isOnHold);
    holdBtn.querySelector('.label').textContent = isOnHold ? 'Resume' : 'Hold';
}

// Contacts Functions
function initializeContacts() {
    const searchInput = document.getElementById('searchInput');
    const addContactBtn = document.getElementById('addContactBtn');

    searchInput.addEventListener('input', async (e) => {
        const query = e.target.value.trim().slice(0, MAX_SEARCH_LENGTH);
        if (query) {
            await searchContacts(query);
        } else {
            renderContacts(contacts);
        }
    });

    addContactBtn.addEventListener('click', () => {
        openContactModal();
    });
}

async function loadContacts() {
    try {
        const result = await invoke('get_contacts');
        // Validate response structure
        if (!Array.isArray(result)) {
            console.error('Invalid contacts response: not an array');
            contacts = [];
        } else {
            // Filter and validate each contact
            contacts = result.filter(c =>
                c && typeof c.id === 'string' &&
                typeof c.name === 'string' &&
                typeof c.sip_uri === 'string'
            );
        }
        renderContacts(contacts);
    } catch (error) {
        console.error('Failed to load contacts:', error);
        contacts = [];
    }
}

async function searchContacts(query) {
    try {
        const results = await invoke('search_contacts', { query });
        renderContacts(results);
    } catch (error) {
        console.error('Failed to search contacts:', error);
        // Fall back to client-side filtering
        filterContacts(query);
    }
}

function renderContacts(contactsToRender) {
    const contactsList = document.getElementById('contactsList');
    contactsList.innerHTML = '';

    // Sort by favorites first, then alphabetically
    const sorted = [...contactsToRender].sort((a, b) => {
        if (a.favorite !== b.favorite) return b.favorite ? 1 : -1;
        return a.name.localeCompare(b.name);
    });

    sorted.forEach(contact => {
        const item = document.createElement('div');
        item.className = 'contact-item';

        // Escape HTML to prevent XSS
        const safeName = escapeHtml(contact.name);
        const safeUri = escapeHtml(contact.sip_uri);
        const safeId = escapeHtml(contact.id);

        item.innerHTML = `
            <div class="contact-info">
                <div class="contact-name">${contact.favorite ? '⭐ ' : ''}${safeName}</div>
                <div class="contact-uri">${safeUri}</div>
            </div>
            <div class="contact-actions">
                <button class="contact-btn call" data-id="${safeId}" title="Call">📞</button>
                <button class="contact-btn edit" data-id="${safeId}" title="Edit">✏️</button>
                <button class="contact-btn delete" data-id="${safeId}" title="Delete">🗑️</button>
            </div>
        `;

        // Add event listeners
        item.querySelector('.contact-btn.call').addEventListener('click', () => {
            makeCall(contact.sip_uri);
        });

        item.querySelector('.contact-btn.edit').addEventListener('click', () => {
            openContactModal(contact);
        });

        item.querySelector('.contact-btn.delete').addEventListener('click', async () => {
            if (confirm(`Delete contact ${escapeHtml(contact.name).slice(0, 50)}?`)) {
                await deleteContact(contact.id);
            }
        });

        contactsList.appendChild(item);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function filterContacts(query) {
    // Input validation: enforce max length and sanitize
    if (!query) {
        renderContacts(contacts);
        return;
    }

    // Trim and enforce max length
    const sanitizedQuery = query.trim().slice(0, MAX_SEARCH_LENGTH).toLowerCase();

    if (!sanitizedQuery) {
        renderContacts(contacts);
        return;
    }

    // Filter with sanitized search term
    const filtered = contacts.filter(contact =>
        contact.name.toLowerCase().includes(sanitizedQuery) ||
        contact.sip_uri.toLowerCase().includes(sanitizedQuery)
    );
    renderContacts(filtered);
}

function openContactModal(contact = null) {
    const modal = document.getElementById('contactModal');
    const modalTitle = document.getElementById('modalTitle');
    const nameInput = document.getElementById('contactName');
    const uriInput = document.getElementById('contactUri');
    const favoriteCheckbox = document.getElementById('contactFavorite');

    if (contact) {
        modalTitle.textContent = 'Edit Contact';
        nameInput.value = contact.name;
        uriInput.value = contact.sip_uri;
        favoriteCheckbox.checked = contact.favorite;
        modal.dataset.editId = contact.id;
    } else {
        modalTitle.textContent = 'Add Contact';
        nameInput.value = '';
        uriInput.value = '';
        favoriteCheckbox.checked = false;
        delete modal.dataset.editId;
    }

    modal.classList.add('active');
    nameInput.focus();
}

function closeContactModal() {
    const modal = document.getElementById('contactModal');
    modal.classList.remove('active');
}

async function saveContact() {
    const modal = document.getElementById('contactModal');
    const name = document.getElementById('contactName').value.trim();
    const uri = document.getElementById('contactUri').value.trim();
    const favorite = document.getElementById('contactFavorite').checked;

    if (!name || !uri) {
        alert('Please fill in all required fields');
        return;
    }

    // Validate SIP URI format
    if (!isValidSipUri(uri)) {
        alert('Please enter a valid SIP URI (e.g., user@domain.com or sip:user@domain.com)');
        return;
    }

    const contact = {
        id: modal.dataset.editId || generateSecureId(),
        name: name.slice(0, MAX_CONTACT_NAME),
        sip_uri: uri.slice(0, MAX_URI_LENGTH),
        phone_numbers: [],
        favorite,
        avatar_path: null,
        organization: null,
        notes: null
    };

    if (!rateLimiter.canCall('save_contact')) return;
    try {
        if (modal.dataset.editId) {
            await invoke('update_contact', { contact });
        } else {
            await invoke('add_contact', { contact });
        }

        await loadContacts();
        // Also refresh favorites if they're being shown
        renderFavorites();
        closeContactModal();
    } catch (error) {
        console.error('Failed to save contact:', error);
        safeAlert('Failed to save contact');
    }
}

function isValidSipUri(uri) {
    // Basic SIP URI validation
    const sipPattern = /^(sips?:)?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return sipPattern.test(uri);
}

async function deleteContact(id) {
    if (!rateLimiter.canCall('delete_contact')) return;
    try {
        await invoke('delete_contact', { id });
        await loadContacts();
        // Also refresh favorites if they're being shown
        renderFavorites();
    } catch (error) {
        console.error('Failed to delete contact:', error);
        safeAlert('Failed to delete contact');
    }
}

// ============================================================================
// Favorites / Speed Dial Functions
// ============================================================================

function initializeFavorites() {
    // Load favorites when tab is shown
    const favoritesTab = document.querySelector('[data-tab="favorites"]');
    if (favoritesTab) {
        favoritesTab.addEventListener('click', () => {
            renderFavorites();
        });
    }
}

function renderFavorites() {
    const speedDialGrid = document.getElementById('speedDialGrid');
    const favoritesEmpty = document.getElementById('favoritesEmpty');
    if (!speedDialGrid) return;

    // Get only favorite contacts
    const favorites = contacts.filter(c => c.favorite);

    speedDialGrid.innerHTML = '';

    if (favorites.length === 0) {
        if (favoritesEmpty) favoritesEmpty.style.display = 'flex';
        return;
    }

    if (favoritesEmpty) favoritesEmpty.style.display = 'none';

    // Sort alphabetically
    const sorted = [...favorites].sort((a, b) => a.name.localeCompare(b.name));

    sorted.forEach(contact => {
        const btn = document.createElement('button');
        btn.className = 'speed-dial-btn';

        // Get initials for avatar
        const initials = getInitials(contact.name);
        const safeName = escapeHtml(contact.name);
        const safeUri = escapeHtml(contact.sip_uri);

        btn.innerHTML = `
            <div class="speed-dial-avatar">${initials}</div>
            <div class="speed-dial-name">${safeName}</div>
            <div class="speed-dial-uri">${safeUri}</div>
        `;

        btn.title = `Call ${contact.name}`;
        btn.addEventListener('click', () => {
            makeCall(contact.sip_uri);
        });

        speedDialGrid.appendChild(btn);
    });
}

function getInitials(name) {
    if (!name) return '?';
    const parts = name.trim().split(/\s+/);
    if (parts.length === 1) {
        return parts[0].charAt(0).toUpperCase();
    }
    return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
}

// Recents Functions
let allCallHistory = []; // Store full call history for filtering

function initializeRecents() {
    // Load call history when recents tab is shown
    const recentsTab = document.querySelector('[data-tab="recents"]');
    if (recentsTab) {
        recentsTab.addEventListener('click', async () => {
            await loadCallHistory();
        });
    }

    // Clear call history button
    const clearRecentsBtn = document.getElementById('clearRecentsBtn');
    if (clearRecentsBtn) {
        clearRecentsBtn.addEventListener('click', async () => {
            // Use safeAlert for confirmation since native confirm may be blocked
            try {
                await invoke('clear_call_history');
                await loadCallHistory(); // Reload to show empty list
                safeAlert('Call history cleared');
            } catch (error) {
                safeAlert('Failed to clear call history: ' + error);
            }
        });
    }

    // Search filter for call history
    const recentsSearchInput = document.getElementById('recentsSearchInput');
    if (recentsSearchInput) {
        recentsSearchInput.addEventListener('input', (e) => {
            // Pass raw value to filter function which will sanitize
            filterCallHistory(e.target.value);
        });
    }
}

async function loadCallHistory() {
    try {
        const history = await invoke('get_call_history');
        allCallHistory = history || [];
        renderCallHistory(allCallHistory);

        // Clear search input when loading fresh history
        const recentsSearchInput = document.getElementById('recentsSearchInput');
        if (recentsSearchInput) {
            recentsSearchInput.value = '';
        }
    } catch (error) {
        console.error('Failed to load call history:', error);
        allCallHistory = [];
        renderCallHistory([]);
    }
}

function filterCallHistory(searchTerm) {
    // Input validation: enforce max length and sanitize
    if (!searchTerm) {
        renderCallHistory(allCallHistory);
        return;
    }

    // Trim and enforce max length
    const sanitizedTerm = searchTerm.trim().slice(0, MAX_SEARCH_LENGTH).toLowerCase();

    if (!sanitizedTerm) {
        renderCallHistory(allCallHistory);
        return;
    }

    // Filter with sanitized search term
    const filtered = allCallHistory.filter(entry => {
        // Search in remote URI
        const uriMatch = entry.remote_uri.toLowerCase().includes(sanitizedTerm);

        // Search in contact name if available
        const nameMatch = entry.contact_name &&
                         entry.contact_name.toLowerCase().includes(sanitizedTerm);

        // Search in direction
        const directionMatch = entry.direction.toLowerCase().includes(sanitizedTerm);

        return uriMatch || nameMatch || directionMatch;
    });

    renderCallHistory(filtered);
}

function renderCallHistory(history) {
    const recentsList = document.getElementById('recentsList');
    if (!recentsList) return;

    recentsList.innerHTML = '';

    // Sort by most recent first
    const sorted = [...history].sort((a, b) => {
        const timeA = new Date(a.end_time).getTime();
        const timeB = new Date(b.end_time).getTime();
        return timeB - timeA;
    });

    sorted.forEach(entry => {
        const item = document.createElement('div');
        item.className = 'recent-item';

        // Determine direction and icon
        const isOutbound = entry.direction === 'Outbound';
        const isMissed = entry.duration_secs === null || entry.duration_secs === 0;
        const directionClass = isMissed ? 'missed' : (isOutbound ? 'outbound' : 'inbound');

        // Format time (relative or absolute)
        const callTime = new Date(entry.end_time);
        const now = new Date();
        const diffMs = now - callTime;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        let timeStr;
        if (diffMins < 1) {
            timeStr = 'Just now';
        } else if (diffMins < 60) {
            timeStr = `${diffMins}m ago`;
        } else if (diffHours < 24) {
            timeStr = `${diffHours}h ago`;
        } else if (diffDays === 1) {
            timeStr = 'Yesterday';
        } else if (diffDays < 7) {
            timeStr = `${diffDays}d ago`;
        } else {
            timeStr = callTime.toLocaleDateString();
        }

        // Format duration
        const durationStr = entry.duration_secs
            ? formatDuration(entry.duration_secs)
            : (isMissed ? 'Missed' : 'No answer');

        // Extract just the number/user part from SIP URI
        const extractNumber = (sipUri) => {
            // Remove sip: or sips: prefix
            let uri = sipUri.replace(/^sips?:/, '');
            // Extract the part before @ (the user/number part)
            const atIndex = uri.indexOf('@');
            if (atIndex !== -1) {
                uri = uri.substring(0, atIndex);
            }
            return uri;
        };

        // Get display name or just the number
        const displayName = escapeHtml(entry.remote_display_name || extractNumber(entry.remote_uri));
        const uri = entry.remote_display_name ? escapeHtml(extractNumber(entry.remote_uri)) : '';

        // Direction icon (phone arrow)
        const arrowIcon = `<svg class="recent-direction-icon ${directionClass}" viewBox="0 0 24 24" fill="currentColor">
            <path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z" />
        </svg>`;

        item.innerHTML = `
            <div class="recent-item-main">
                ${arrowIcon}
                <div class="recent-info">
                    <div class="recent-name">${displayName}</div>
                    ${uri ? `<div class="recent-uri">${uri}</div>` : ''}
                </div>
            </div>
            <div class="recent-meta">
                <div class="recent-time">${timeStr}</div>
                <div class="recent-duration">${durationStr}</div>
            </div>
        `;

        // Click to call back
        item.addEventListener('click', () => {
            makeCall(entry.remote_uri);
            switchTab('dialer');
        });

        recentsList.appendChild(item);
    });
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) {
        return `${hours}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    } else {
        return `${minutes}:${String(secs).padStart(2, '0')}`;
    }
}

// Call Control Functions
function initializeCall() {
    const muteBtn = document.getElementById('muteBtn');
    const holdBtn = document.getElementById('holdBtn');
    const keypadBtn = document.getElementById('keypadBtn');
    const transferBtn = document.getElementById('transferBtn');
    const hangupBtn = document.getElementById('hangupBtn');

    muteBtn.addEventListener('click', async () => {
        try {
            isMuted = await invoke('toggle_mute');
            updateMuteButton();
        } catch (error) {
            console.error('Failed to toggle mute:', error);
        }
    });

    holdBtn.addEventListener('click', async () => {
        try {
            isOnHold = await invoke('toggle_hold');
            updateHoldButton();
        } catch (error) {
            console.error('Failed to toggle hold:', error);
        }
    });

    keypadBtn.addEventListener('click', () => {
        showDtmfKeypad();
    });

    transferBtn.addEventListener('click', async () => {
        const target = prompt('Enter transfer target (SIP URI):');
        if (target) {
            // Validate transfer target
            const trimmedTarget = target.trim().slice(0, MAX_URI_LENGTH);
            if (!isValidSipUri(trimmedTarget)) {
                safeAlert('Please enter a valid SIP URI (e.g., user@domain.com or sip:user@domain.com)');
                return;
            }
            if (!rateLimiter.canCall('transfer_call')) return;
            try {
                await invoke('transfer_call', { target: trimmedTarget });
            } catch (error) {
                console.error('Failed to transfer call:', error);
                safeAlert('Failed to transfer call');
            }
        }
    });

    // Track if hangup is in progress to prevent multiple rapid calls
    let hangupInProgress = false;

    hangupBtn.addEventListener('click', async () => {
        // Debounce: prevent multiple rapid hangup attempts
        if (hangupInProgress) {
            console.log('Hangup already in progress, ignoring');
            return;
        }
        hangupInProgress = true;

        try {
            await invoke('end_call');
        } catch (error) {
            console.error('Failed to end call:', error);
        } finally {
            // Always reset state and update UI, even on error
            hangupInProgress = false;
            endCall();
        }
    });

    // Incoming call modal buttons
    document.getElementById('acceptCallBtn').addEventListener('click', () => {
        if (incomingCallId) acceptIncomingCall(incomingCallId);
    });
    document.getElementById('rejectCallBtn').addEventListener('click', () => {
        if (incomingCallId) rejectIncomingCall(incomingCallId);
    });
}

function showDtmfKeypad() {
    // Create a simple DTMF keypad overlay
    const overlay = document.createElement('div');
    overlay.className = 'dtmf-overlay';
    overlay.innerHTML = `
        <div class="dtmf-keypad">
            <h3>DTMF Keypad</h3>
            <div class="dtmf-grid">
                <button class="dtmf-btn" data-digit="1">1</button>
                <button class="dtmf-btn" data-digit="2">2</button>
                <button class="dtmf-btn" data-digit="3">3</button>
                <button class="dtmf-btn" data-digit="4">4</button>
                <button class="dtmf-btn" data-digit="5">5</button>
                <button class="dtmf-btn" data-digit="6">6</button>
                <button class="dtmf-btn" data-digit="7">7</button>
                <button class="dtmf-btn" data-digit="8">8</button>
                <button class="dtmf-btn" data-digit="9">9</button>
                <button class="dtmf-btn" data-digit="*">*</button>
                <button class="dtmf-btn" data-digit="0">0</button>
                <button class="dtmf-btn" data-digit="#">#</button>
            </div>
            <button class="dtmf-close">Close</button>
        </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelectorAll('.dtmf-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const digit = btn.dataset.digit;
            playDtmfTone(digit);
            try {
                await invoke('send_dtmf', { digit });
                console.log('Sent DTMF:', digit);
            } catch (error) {
                console.error('Failed to send DTMF:', error);
            }
        });
    });

    overlay.querySelector('.dtmf-close').addEventListener('click', () => {
        overlay.remove();
    });

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            overlay.remove();
        }
    });
}

// Settings Functions
function initializeSettings() {
    const registerBtn = document.getElementById('registerBtn');
    const unregisterBtn = document.getElementById('unregisterBtn');
    const openConfigBtn = document.getElementById('openConfigBtn');
    const saveContactBtn = document.getElementById('saveContactBtn');
    const cancelContactBtn = document.getElementById('cancelContactBtn');
    const saveSipSettingsBtn = document.getElementById('saveSipSettingsBtn');
    const saveAudioSettingsBtn = document.getElementById('saveAudioSettingsBtn');

    // Load SIP settings on init
    loadSipSettings();

    // Load audio settings on init
    loadAudioSettings();

    // Save SIP settings button
    if (saveSipSettingsBtn) {
        console.log('Save SIP Settings button found, adding click handler');
        saveSipSettingsBtn.addEventListener('click', async () => {
            console.log('Save SIP Settings button clicked');
            await saveSipSettings();
        });
    } else {
        console.error('Save SIP Settings button NOT found!');
    }

    // Save audio settings button
    if (saveAudioSettingsBtn) {
        saveAudioSettingsBtn.addEventListener('click', async () => {
            await saveAudioSettings();
        });
    }

    // Open config file button
    if (openConfigBtn) {
        openConfigBtn.addEventListener('click', async () => {
            if (!rateLimiter.canCall('open_config_file')) return;
            try {
                await invoke('open_config_file');
            } catch (error) {
                console.error('Failed to open config file:', error);
                safeAlert('Failed to open config file');
            }
        });
    }

    registerBtn.addEventListener('click', async () => {
        if (!rateLimiter.canCall('register_sip')) return;
        try {
            registerBtn.disabled = true;
            registerBtn.textContent = 'Registering...';
            await invoke('register_sip');
            updateStatus('online');
            registrationState = 'registered';
        } catch (error) {
            console.error('Failed to register:', error);
            safeAlert('Failed to register');
        } finally {
            registerBtn.disabled = false;
            registerBtn.textContent = 'Register';
        }
    });

    unregisterBtn.addEventListener('click', async () => {
        if (!rateLimiter.canCall('unregister_sip')) return;
        try {
            await invoke('unregister_sip');
            updateStatus('offline');
            registrationState = 'unregistered';
        } catch (error) {
            console.error('Failed to unregister:', error);
            safeAlert('Failed to unregister');
        }
    });

    saveContactBtn.addEventListener('click', async () => {
        await saveContact();
    });

    cancelContactBtn.addEventListener('click', () => {
        closeContactModal();
    });
}

async function updateRegistrationStatus() {
    try {
        const status = await invoke('get_registration_status');
        registrationState = status.state;
        updateStatus(registrationState === 'registered' ? 'online' : 'offline');
    } catch (error) {
        console.error('Failed to get registration status:', error);
    }
}

async function loadAudioDevices() {
    try {
        const inputDevices = await invoke('get_input_devices');
        const outputDevices = await invoke('get_output_devices');

        const inputSelect = document.getElementById('inputDevice');
        const outputSelect = document.getElementById('outputDevice');

        if (inputSelect) {
            inputSelect.innerHTML = '<option value="">Default</option>';
            inputDevices.forEach(device => {
                const option = document.createElement('option');
                option.value = device.name;
                option.textContent = device.display_name;
                if (device.is_default) option.selected = true;
                inputSelect.appendChild(option);
            });

            inputSelect.addEventListener('change', async () => {
                const deviceName = inputSelect.value || null;
                try {
                    await invoke('set_input_device', { deviceName });
                } catch (error) {
                    console.error('Failed to set input device:', error);
                }
            });
        }

        if (outputSelect) {
            outputSelect.innerHTML = '<option value="">Default</option>';
            outputDevices.forEach(device => {
                const option = document.createElement('option');
                option.value = device.name;
                option.textContent = device.display_name;
                if (device.is_default) option.selected = true;
                outputSelect.appendChild(option);
            });

            outputSelect.addEventListener('change', async () => {
                const deviceName = outputSelect.value || null;
                try {
                    await invoke('set_output_device', { deviceName });
                } catch (error) {
                    console.error('Failed to set output device:', error);
                }
            });
        }
    } catch (error) {
        console.error('Failed to load audio devices:', error);
    }
}

// Status Management
function updateStatus(status) {
    const statusIndicator = document.getElementById('status');
    const statusText = statusIndicator.querySelector('.status-text');

    if (status === 'online') {
        statusIndicator.classList.add('online');
        statusText.textContent = 'Online';
    } else {
        statusIndicator.classList.remove('online');
        statusText.textContent = 'Offline';
    }
}

// ============================================================================
// Certificate / Smart Card Management
// ============================================================================

let certificates = [];
let selectedCertThumbprint = null;
let pinCallback = null; // Called when PIN is submitted

// Initialize certificate UI
async function initializeCertificates() {
    const refreshBtn = document.getElementById('refreshCertsBtn');
    const submitPinBtn = document.getElementById('submitPinBtn');
    const cancelPinBtn = document.getElementById('cancelPinBtn');
    const pinInput = document.getElementById('pinInput');

    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            await loadCertificates();
        });
    }

    if (submitPinBtn) {
        submitPinBtn.addEventListener('click', async () => {
            await submitPin();
        });
    }

    if (cancelPinBtn) {
        cancelPinBtn.addEventListener('click', () => {
            closePinModal();
        });
    }

    if (pinInput) {
        pinInput.addEventListener('keypress', async (e) => {
            if (e.key === 'Enter') {
                await submitPin();
            }
        });
    }

    // Listen for PIN required events from backend
    try {
        await listen('pin-required', (event) => {
            console.log('PIN required:', event.payload);
            const { operation, thumbprint } = event.payload;
            openPinModal(thumbprint, operation);
        });
    } catch (listenError) {
        console.error('Failed to set up PIN listener:', listenError);
    }

    // Initial load
    await loadCertificates();
    await loadSelectedCertificate();
}

// Load certificates from the store
async function loadCertificates() {
    const certList = document.getElementById('certList');
    const certStatus = document.getElementById('certStatus');

    if (!certList) return;

    try {
        certList.innerHTML = '<div class="cert-loading">Loading certificates...</div>';
        const result = await invoke('get_certificates');

        // Handle null/undefined response
        certificates = result || [];

        if (certificates.length === 0) {
            certList.innerHTML = '<div class="cert-empty">No certificates found. Insert your smart card.</div>';
            if (certStatus) {
                certStatus.textContent = 'No certificates available';
                certStatus.classList.remove('selected');
            }
        } else {
            renderCertificates();

            // Auto-select if there's only one valid certificate and none is currently selected
            if (certificates.length === 1 && !selectedCertThumbprint) {
                const cert = certificates[0];
                if (cert.is_valid) {
                    console.log('Auto-selecting single certificate:', cert.subject_cn);
                    await selectCertificate(cert);
                }
            }
        }
    } catch (error) {
        console.error('Failed to load certificates:', error);
        certificates = [];
        certList.innerHTML = `<div class="cert-error">Failed to load certificates: ${error}</div>`;
    }
}

// Load the currently selected certificate
async function loadSelectedCertificate() {
    try {
        selectedCertThumbprint = await invoke('get_selected_certificate');
        updateCertStatus();
    } catch (error) {
        console.error('Failed to load selected certificate:', error);
    }
}

// Render the certificate list
function renderCertificates() {
    const certList = document.getElementById('certList');
    if (!certList) return;

    certList.innerHTML = '';

    certificates.forEach(cert => {
        const item = document.createElement('div');
        item.className = 'cert-item';

        if (cert.thumbprint === selectedCertThumbprint) {
            item.classList.add('selected');
        }
        if (!cert.is_valid) {
            item.classList.add('expired');
        }

        const safeName = escapeHtml(cert.subject_cn || 'Unknown');
        const safeIssuer = escapeHtml(cert.issuer_cn || 'Unknown Issuer');
        const validityClass = cert.is_valid ? '' : 'expired';
        const validityText = cert.is_valid
            ? `Valid until ${cert.not_after}`
            : `EXPIRED: ${cert.not_after}`;

        item.innerHTML = `
            <div class="cert-item-info">
                <div class="cert-item-name">${safeName}</div>
                <div class="cert-item-issuer">Issued by: ${safeIssuer}</div>
                <div class="cert-item-validity ${validityClass}">${validityText}</div>
            </div>
            <div class="cert-item-actions">
                <button class="cert-item-btn select" title="Select certificate">
                    ${cert.thumbprint === selectedCertThumbprint ? 'Selected' : 'Select'}
                </button>
            </div>
        `;

        const selectBtn = item.querySelector('.cert-item-btn.select');
        selectBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            await selectCertificate(cert);
        });

        // Also allow clicking the whole item
        item.addEventListener('click', async () => {
            await selectCertificate(cert);
        });

        certList.appendChild(item);
    });
}

// Select a certificate
async function selectCertificate(cert) {
    if (!cert.is_valid) {
        safeAlert('Cannot select an expired certificate. Please choose a valid certificate.');
        return;
    }

    if (!rateLimiter.canCall('select_certificate')) return;

    try {
        // Check if private key is available (smart card present)
        const hasKey = await invoke('check_private_key', { thumbprint: cert.thumbprint });

        if (!hasKey) {
            safeAlert('Smart card not detected. Please insert your CAC/PIV card and try again.');
            return;
        }

        // Select the certificate
        await invoke('select_certificate', { thumbprint: cert.thumbprint });
        selectedCertThumbprint = cert.thumbprint;

        updateCertStatus();
        renderCertificates();

        console.log('Certificate selected:', cert.subject_cn);
    } catch (error) {
        console.error('Failed to select certificate:', error);
        safeAlert('Failed to select certificate');
    }
}

// Update the certificate status display
function updateCertStatus() {
    const certStatus = document.getElementById('certStatus');
    if (!certStatus) return;

    if (selectedCertThumbprint) {
        const cert = certificates.find(c => c.thumbprint === selectedCertThumbprint);
        if (cert) {
            certStatus.textContent = `Selected: ${cert.subject_cn}`;
            certStatus.classList.add('selected');
        } else {
            certStatus.textContent = `Certificate selected (${selectedCertThumbprint.slice(0, 8)}...)`;
            certStatus.classList.add('selected');
        }
    } else {
        certStatus.textContent = 'No certificate selected';
        certStatus.classList.remove('selected');
    }
}

// Clear the selected certificate
async function clearSelectedCertificate() {
    try {
        await invoke('clear_selected_certificate');
        selectedCertThumbprint = null;
        updateCertStatus();
        renderCertificates();
    } catch (error) {
        console.error('Failed to clear certificate:', error);
    }
}

// ============================================================================
// PIN Dialog Management
// ============================================================================

// Open the PIN entry modal
function openPinModal(thumbprint, operation = 'authentication') {
    const modal = document.getElementById('pinModal');
    const certInfo = document.getElementById('pinCertInfo');
    const pinInput = document.getElementById('pinInput');
    const pinError = document.getElementById('pinError');

    if (!modal) return;

    // Find the certificate to display info
    const cert = certificates.find(c => c.thumbprint === thumbprint);
    const certName = cert ? cert.subject_cn : 'Selected certificate';

    certInfo.textContent = `Enter PIN for: ${certName}`;
    pinInput.value = '';
    pinError.textContent = '';

    modal.dataset.thumbprint = thumbprint;
    modal.dataset.operation = operation;

    modal.classList.add('active');
    pinInput.focus();
}

// Close the PIN modal
function closePinModal() {
    const modal = document.getElementById('pinModal');
    if (modal) {
        modal.classList.remove('active');
        document.getElementById('pinInput').value = '';
        document.getElementById('pinError').textContent = '';
        delete modal.dataset.thumbprint;
        delete modal.dataset.operation;
    }

    // Call callback with cancellation
    if (pinCallback) {
        pinCallback(null);
        pinCallback = null;
    }
}

// Submit the PIN
async function submitPin() {
    const modal = document.getElementById('pinModal');
    const pinInput = document.getElementById('pinInput');
    const pinError = document.getElementById('pinError');
    const submitBtn = document.getElementById('submitPinBtn');

    const pin = pinInput.value;
    const thumbprint = modal.dataset.thumbprint;

    if (!pin) {
        pinError.textContent = 'Please enter your PIN';
        return;
    }

    if (pin.length < 4) {
        pinError.textContent = 'PIN must be at least 4 digits';
        return;
    }

    try {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Verifying...';
        pinError.textContent = '';

        const success = await invoke('verify_pin', { thumbprint, pin });

        if (success) {
            // Securely clear PIN from input by overwriting multiple times
            pinInput.value = '0'.repeat(pin.length);
            pinInput.value = 'X'.repeat(pin.length);
            pinInput.value = '';

            closePinModal();

            // Call callback with success
            if (pinCallback) {
                pinCallback(pin);
                pinCallback = null;
            }
        } else {
            pinError.textContent = 'PIN incorrect. Please try again.';
            // Overwrite before clearing
            pinInput.value = '0'.repeat(pin.length);
            pinInput.value = '';
            pinInput.focus();
        }
    } catch (error) {
        // Don't log the actual error as it might contain sensitive data
        console.error('PIN verification failed');
        pinError.textContent = 'Verification failed. Please try again.';
        // Overwrite before clearing
        pinInput.value = '0'.repeat(pin.length);
        pinInput.value = '';
        pinInput.focus();
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Unlock';
    }
}

// Request PIN entry and return a promise
function requestPin(thumbprint, operation = 'authentication') {
    return new Promise((resolve) => {
        pinCallback = resolve;
        openPinModal(thumbprint, operation);
    });
}

// ============================================================================
// SIP Settings Management
// ============================================================================

// Load SIP settings from backend
async function loadSipSettings() {
    try {
        const settings = await invoke('get_sip_settings');
        if (settings) {
            const displayNameInput = document.getElementById('sipDisplayName');
            const usernameInput = document.getElementById('sipUsername');
            const domainInput = document.getElementById('sipDomain');
            const callerIdInput = document.getElementById('sipCallerId');
            const registrarInput = document.getElementById('sipRegistrar');
            const portInput = document.getElementById('sipPort');
            const transportSelect = document.getElementById('sipTransport');
            const autoRegisterCheckbox = document.getElementById('sipAutoRegister');

            if (displayNameInput) displayNameInput.value = settings.display_name || '';
            if (usernameInput) usernameInput.value = settings.username || '';
            if (domainInput) domainInput.value = settings.domain || '';
            if (callerIdInput) callerIdInput.value = settings.caller_id || '';
            if (registrarInput) registrarInput.value = settings.registrar || '';
            if (portInput) portInput.value = settings.port || 5060;
            if (transportSelect) transportSelect.value = settings.transport || 'tls';
            if (autoRegisterCheckbox) autoRegisterCheckbox.checked = settings.auto_register !== false;

            // Load digest auth credentials if available
            const authUsernameInput = document.getElementById('authUsername');
            const authPasswordInput = document.getElementById('authPassword');
            if (authUsernameInput && settings.auth_username) {
                authUsernameInput.value = settings.auth_username;
            }
            // Note: password is never loaded from backend for security

            console.log('SIP settings loaded');
        }
    } catch (error) {
        console.log('Could not load SIP settings:', error);
    }
}

// Save SIP settings to backend
async function saveSipSettings() {
    console.log('saveSipSettings() called');
    if (!rateLimiter.canCall('save_sip_settings')) {
        console.log('Rate limited, skipping');
        return;
    }

    const displayName = document.getElementById('sipDisplayName')?.value.trim() || '';
    const username = document.getElementById('sipUsername')?.value.trim() || '';
    const domain = document.getElementById('sipDomain')?.value.trim() || '';
    const callerId = document.getElementById('sipCallerId')?.value.trim() || '';
    const registrar = document.getElementById('sipRegistrar')?.value.trim() || '';
    const port = parseInt(document.getElementById('sipPort')?.value, 10) || 5060;
    const transport = document.getElementById('sipTransport')?.value || 'tls';
    const autoRegister = document.getElementById('sipAutoRegister')?.checked !== false;

    // Basic validation
    if (!username || !domain) {
        safeAlert('Please enter at least a username and domain');
        return;
    }

    // Validate port range
    if (port < 1 || port > 65535) {
        safeAlert('Port must be between 1 and 65535');
        return;
    }

    const settings = {
        display_name: displayName,
        username: username,
        domain: domain,
        registrar: registrar || domain, // Use domain if registrar not specified
        port: port,
        transport: transport,
        auto_register: autoRegister,
        caller_id: callerId || null,
    };

    // Add digest auth credentials if feature is enabled and fields are filled
    const authUsernameEl = document.getElementById('authUsername');
    const authPasswordEl = document.getElementById('authPassword');
    const authUsername = authUsernameEl?.value.trim();
    const authPassword = authPasswordEl?.value;

    console.log('Auth fields:', {
        usernameEl: !!authUsernameEl,
        passwordEl: !!authPasswordEl,
        username: authUsername,
        passwordLen: authPassword?.length || 0
    });

    if (authUsername) {
        settings.auth_username = authUsername;
    }
    if (authPassword) {
        settings.auth_password = authPassword;
    }

    try {
        await invoke('save_sip_settings', { settings });
        safeAlert('SIP settings saved successfully');
        console.log('SIP settings saved:', settings.username + '@' + settings.domain);
    } catch (error) {
        console.error('Failed to save SIP settings:', error);
        safeAlert('Failed to save SIP settings: ' + error);
    }
}

// ============================================================================
// Audio Settings Management
// ============================================================================

// Load audio settings from backend
async function loadAudioSettings() {
    try {
        const settings = await invoke('get_audio_settings');
        if (settings) {
            const codecSelect = document.getElementById('audioCodec');
            const echoCancellationCheckbox = document.getElementById('audioEchoCancellation');
            const noiseSuppressionCheckbox = document.getElementById('audioNoiseSuppression');

            if (codecSelect) codecSelect.value = settings.preferred_codec || 'opus';
            if (echoCancellationCheckbox) echoCancellationCheckbox.checked = settings.echo_cancellation !== false;
            if (noiseSuppressionCheckbox) noiseSuppressionCheckbox.checked = settings.noise_suppression !== false;

            console.log('Audio settings loaded: codec=' + settings.preferred_codec);
        }
    } catch (error) {
        console.log('Could not load audio settings:', error);
    }
}

// Save audio settings to backend
async function saveAudioSettings() {
    if (!rateLimiter.canCall('save_audio_settings')) return;

    const preferredCodec = document.getElementById('audioCodec')?.value || 'opus';
    const echoCancellation = document.getElementById('audioEchoCancellation')?.checked !== false;
    const noiseSuppression = document.getElementById('audioNoiseSuppression')?.checked !== false;

    const settings = {
        preferred_codec: preferredCodec,
        echo_cancellation: echoCancellation,
        noise_suppression: noiseSuppression,
        jitter_buffer_min_ms: 20,  // Default values
        jitter_buffer_max_ms: 200,
    };

    try {
        await invoke('save_audio_settings', { settings });
        safeAlert('Audio settings saved successfully');
        console.log('Audio settings saved: codec=' + preferredCodec);
    } catch (error) {
        console.error('Failed to save audio settings:', error);
        safeAlert('Failed to save audio settings: ' + error);
    }
}
