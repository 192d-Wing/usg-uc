// USG SIP Soft Client - Frontend Application Logic

// Use Tauri 2.0 invoke API
const invoke = window.__TAURI_INVOKE__ || window.__TAURI_INTERNALS__?.invoke || function() {
    console.error('Tauri API not available');
    return Promise.reject('Tauri API not available');
};

// Application State
let currentTab = 'dialer';
let contacts = [];
let callActive = false;
let callDurationInterval = null;
let callStartTime = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', async () => {
    initializeTabs();
    initializeDialer();
    initializeContacts();
    initializeCall();
    initializeSettings();
    await loadContacts();
    await loadSettings();
});

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

// Dialer Functions
function initializeDialer() {
    const dialInput = document.getElementById('dialInput');
    const dialpadBtns = document.querySelectorAll('.dialpad-btn');
    const backspaceBtn = document.getElementById('backspaceBtn');
    const callBtn = document.getElementById('callBtn');

    dialpadBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const digit = btn.dataset.digit;
            dialInput.value += digit;
        });
    });

    backspaceBtn.addEventListener('click', () => {
        dialInput.value = dialInput.value.slice(0, -1);
    });

    callBtn.addEventListener('click', async () => {
        const target = dialInput.value.trim();
        if (target) {
            await makeCall(target);
        }
    });
}

async function makeCall(target) {
    try {
        const result = await invoke('make_call', { target });
        console.log('Call initiated:', result);
        startCall(target);
        switchTab('call');
    } catch (error) {
        console.error('Failed to make call:', error);
        alert(`Failed to make call: ${error}`);
    }
}

function startCall(target) {
    callActive = true;
    callStartTime = Date.now();
    document.getElementById('callTarget').textContent = target;

    // Enable call controls
    document.getElementById('muteBtn').disabled = false;
    document.getElementById('holdBtn').disabled = false;
    document.getElementById('keypadBtn').disabled = false;
    document.getElementById('transferBtn').disabled = false;
    document.getElementById('hangupBtn').disabled = false;

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

    if (callDurationInterval) {
        clearInterval(callDurationInterval);
        callDurationInterval = null;
    }

    document.getElementById('callTarget').textContent = '';
    document.getElementById('callDuration').textContent = '00:00';

    // Disable call controls
    document.getElementById('muteBtn').disabled = true;
    document.getElementById('holdBtn').disabled = true;
    document.getElementById('keypadBtn').disabled = true;
    document.getElementById('transferBtn').disabled = true;
    document.getElementById('hangupBtn').disabled = true;

    // Reset button states
    document.getElementById('muteBtn').classList.remove('active');
    document.getElementById('holdBtn').classList.remove('active');

    // Update status
    updateStatus('offline');
}

// Contacts Functions
function initializeContacts() {
    const searchInput = document.getElementById('searchInput');
    const addContactBtn = document.getElementById('addContactBtn');

    searchInput.addEventListener('input', (e) => {
        filterContacts(e.target.value);
    });

    addContactBtn.addEventListener('click', () => {
        openContactModal();
    });
}

async function loadContacts() {
    try {
        contacts = await invoke('get_contacts');
        renderContacts(contacts);
    } catch (error) {
        console.error('Failed to load contacts:', error);
    }
}

function renderContacts(contactsToRender) {
    const contactsList = document.getElementById('contactsList');
    contactsList.innerHTML = '';

    contactsToRender.forEach(contact => {
        const item = document.createElement('div');
        item.className = 'contact-item';

        item.innerHTML = `
            <div class="contact-info">
                <div class="contact-name">${contact.favorite ? '⭐ ' : ''}${contact.name}</div>
                <div class="contact-uri">${contact.sip_uri}</div>
            </div>
            <div class="contact-actions">
                <button class="contact-btn call" data-id="${contact.id}">📞</button>
                <button class="contact-btn edit" data-id="${contact.id}">✏️</button>
                <button class="contact-btn delete" data-id="${contact.id}">🗑️</button>
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
            if (confirm(`Delete contact ${contact.name}?`)) {
                await deleteContact(contact.id);
            }
        });

        contactsList.appendChild(item);
    });
}

function filterContacts(query) {
    const filtered = contacts.filter(contact =>
        contact.name.toLowerCase().includes(query.toLowerCase()) ||
        contact.sip_uri.toLowerCase().includes(query.toLowerCase())
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
        alert('Please fill in all fields');
        return;
    }

    const contact = {
        id: modal.dataset.editId || `${Date.now()}`,
        name,
        sip_uri: uri,
        favorite
    };

    try {
        if (modal.dataset.editId) {
            await invoke('update_contact', { contact });
        } else {
            await invoke('add_contact', { contact });
        }

        await loadContacts();
        closeContactModal();
    } catch (error) {
        console.error('Failed to save contact:', error);
        alert(`Failed to save contact: ${error}`);
    }
}

async function deleteContact(id) {
    try {
        await invoke('delete_contact', { id });
        await loadContacts();
    } catch (error) {
        console.error('Failed to delete contact:', error);
        alert(`Failed to delete contact: ${error}`);
    }
}

// Call Control Functions
function initializeCall() {
    const muteBtn = document.getElementById('muteBtn');
    const holdBtn = document.getElementById('holdBtn');
    const hangupBtn = document.getElementById('hangupBtn');

    muteBtn.addEventListener('click', async () => {
        try {
            const muted = await invoke('toggle_mute');
            muteBtn.classList.toggle('active', muted);
            muteBtn.querySelector('.label').textContent = muted ? 'Unmute' : 'Mute';
        } catch (error) {
            console.error('Failed to toggle mute:', error);
        }
    });

    holdBtn.addEventListener('click', async () => {
        try {
            const held = await invoke('toggle_hold');
            holdBtn.classList.toggle('active', held);
            holdBtn.querySelector('.label').textContent = held ? 'Resume' : 'Hold';
        } catch (error) {
            console.error('Failed to toggle hold:', error);
        }
    });

    hangupBtn.addEventListener('click', async () => {
        try {
            await invoke('end_call');
            endCall();
        } catch (error) {
            console.error('Failed to end call:', error);
        }
    });
}

// Settings Functions
function initializeSettings() {
    const registerBtn = document.getElementById('registerBtn');
    const unregisterBtn = document.getElementById('unregisterBtn');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    const saveContactBtn = document.getElementById('saveContactBtn');
    const cancelContactBtn = document.getElementById('cancelContactBtn');

    registerBtn.addEventListener('click', async () => {
        try {
            await invoke('register_sip');
            updateStatus('online');
            alert('Successfully registered with SIP server');
        } catch (error) {
            console.error('Failed to register:', error);
            alert(`Failed to register: ${error}`);
        }
    });

    unregisterBtn.addEventListener('click', async () => {
        try {
            await invoke('unregister_sip');
            updateStatus('offline');
            alert('Successfully unregistered from SIP server');
        } catch (error) {
            console.error('Failed to unregister:', error);
            alert(`Failed to unregister: ${error}`);
        }
    });

    saveSettingsBtn.addEventListener('click', async () => {
        await saveSettings();
    });

    saveContactBtn.addEventListener('click', async () => {
        await saveContact();
    });

    cancelContactBtn.addEventListener('click', () => {
        closeContactModal();
    });
}

async function loadSettings() {
    try {
        const settings = await invoke('get_sip_settings');
        document.getElementById('username').value = settings.username || '';
        document.getElementById('domain').value = settings.domain || '';
        document.getElementById('proxy').value = settings.proxy || '';
        document.getElementById('port').value = settings.port || 5061;

        // Load audio devices
        const devices = await invoke('get_audio_devices');
        // TODO: Populate device dropdowns
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

async function saveSettings() {
    const settings = {
        username: document.getElementById('username').value.trim(),
        domain: document.getElementById('domain').value.trim(),
        proxy: document.getElementById('proxy').value.trim(),
        port: parseInt(document.getElementById('port').value) || 5061
    };

    try {
        await invoke('update_sip_settings', { settings });
        alert('Settings saved successfully');
    } catch (error) {
        console.error('Failed to save settings:', error);
        alert(`Failed to save settings: ${error}`);
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
