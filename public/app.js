// ── Session Token Interceptor ─────────────────────────────────────────────
// Read the per-session token injected by the Rust launcher via the meta tag.
// Intercept all fetch() calls to /api/* and attach the X-Session-Token header.
(function() {
  'use strict';
  const meta = document.querySelector('meta[name="x-session-token"]');
  const SESSION_TOKEN = meta ? meta.getAttribute('content') : null;

  // If no valid token found, the page was not opened by the launcher — lock down immediately
  if (!SESSION_TOKEN || SESSION_TOKEN === '__SESSION_TOKEN_PLACEHOLDER__' || SESSION_TOKEN.length !== 64) {
    document.body.innerHTML = '';
    document.title = '';
    return;
  }

  // Intercept window.fetch to automatically attach the session token header
  const _originalFetch = window.fetch.bind(window);
  window.fetch = function(resource, options) {
    const url = typeof resource === 'string' ? resource : (resource.url || '');
    if (url.startsWith('/api/') || url.includes('127.0.0.1') || url.includes('localhost')) {
      options = options || {};
      options.headers = Object.assign({}, options.headers || {}, {
        'X-Session-Token': SESSION_TOKEN
      });
    }
    return _originalFetch(resource, options);
  };
})();

// State Management
let selectedFile = null;
let isNodeInitialized = false;
let logOffset = 0;
let statusIntervalId = null;

// Hardcoded Default Connection Values for simplicity
const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 8000;
const DEFAULT_LISTEN_PORT = 9090;

// DOM Elements
const tabLogin = document.getElementById('tab-login-trigger');
const tabRegister = document.getElementById('tab-register-trigger');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const authCard = document.getElementById('auth-card');
const transferCard = document.getElementById('transfer-card');
const statusDot = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');
const addressBanner = document.getElementById('address-banner-section');
const myAddressText = document.getElementById('my-address-text');
const btnCopyAddress = document.getElementById('btn-copy-address');
const consoleOutput = document.getElementById('console-output');
const btnClearLogs = document.getElementById('btn-clear-logs');
const btnRefreshFiles = document.getElementById('btn-refresh-files');
const filesTableBody = document.getElementById('files-table-body');
const dropzone = document.getElementById('file-dropzone');
const fileInput = document.getElementById('transfer-file-input');
const selectedFileDetails = document.getElementById('selected-file-details');
const selectedFileName = document.getElementById('selected-file-name');
const selectedFileSize = document.getElementById('selected-file-size');
const btnClearFile = document.getElementById('btn-clear-file');
const transferForm = document.getElementById('transfer-form');
const btnSendSubmit = document.getElementById('btn-send-submit');
const btnShutdownNode = document.getElementById('btn-shutdown-node');
const btnThemeToggle = document.getElementById('btn-theme-toggle');
const btnLogout = document.getElementById('btn-logout');

// --- Dark Mode / Light Mode toggle ---
const savedTheme = localStorage.getItem('theme') || 'light';
if (savedTheme === 'dark') {
  document.body.classList.add('dark-mode');
  btnThemeToggle.textContent = 'LIGHT MODE';
} else {
  document.body.classList.remove('dark-mode');
  btnThemeToggle.textContent = 'DARK MODE';
}

btnThemeToggle.addEventListener('click', () => {
  if (document.body.classList.contains('dark-mode')) {
    document.body.classList.remove('dark-mode');
    btnThemeToggle.textContent = 'DARK MODE';
    localStorage.setItem('theme', 'light');
  } else {
    document.body.classList.add('dark-mode');
    btnThemeToggle.textContent = 'LIGHT MODE';
    localStorage.setItem('theme', 'dark');
  }
});

// --- Tab Navigation ---
tabLogin.addEventListener('click', () => {
  tabLogin.classList.add('active');
  tabRegister.classList.remove('active');
  loginForm.style.display = 'block';
  registerForm.style.display = 'none';
});

tabRegister.addEventListener('click', () => {
  tabRegister.classList.add('active');
  tabLogin.classList.remove('active');
  registerForm.style.display = 'block';
  loginForm.style.display = 'none';
});

// --- Utility: Log Writer ---
function addLocalLog(message, type = 'system') {
  const line = document.createElement('div');
  line.className = `log-line ${type}-line`;
  const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
  line.textContent = `[${timestamp}] [${type.toUpperCase()}] ${message}`;
  consoleOutput.appendChild(line);
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

// --- Clipboard Copy ---
btnCopyAddress.addEventListener('click', () => {
  navigator.clipboard.writeText(myAddressText.textContent)
    .then(() => {
      const originalText = btnCopyAddress.textContent;
      btnCopyAddress.textContent = 'COPIED';
      setTimeout(() => btnCopyAddress.textContent = originalText, 1500);
    })
    .catch(err => addLocalLog('Failed to copy: ' + err, 'error'));
});

// --- Drag and Drop Interface ---
dropzone.addEventListener('click', () => fileInput.click());

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.style.borderStyle = 'solid';
});

dropzone.addEventListener('dragleave', () => {
  dropzone.style.borderStyle = 'dashed';
});

dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.style.borderStyle = 'dashed';
  if (e.dataTransfer.files.length > 0) {
    handleFileSelection(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length > 0) {
    handleFileSelection(fileInput.files[0]);
  }
});

function handleFileSelection(file) {
  selectedFile = file;
  selectedFileName.textContent = file.name;
  
  // Format File Size
  const sizeKB = file.size / 1024;
  if (sizeKB < 1024) {
    selectedFileSize.textContent = `${sizeKB.toFixed(1)} KB`;
  } else {
    selectedFileSize.textContent = `${(sizeKB / 1024).toFixed(1)} MB`;
  }

  selectedFileDetails.style.display = 'flex';
  btnSendSubmit.removeAttribute('disabled');
}

btnClearFile.addEventListener('click', (e) => {
  e.stopPropagation();
  clearSelectedFile();
});

function clearSelectedFile() {
  selectedFile = null;
  fileInput.value = '';
  selectedFileDetails.style.display = 'none';
  btnSendSubmit.setAttribute('disabled', 'true');
}

// --- API Requests ---

// Register User
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('register-username').value.trim();
  const password = document.getElementById('register-password').value;
  
  const submitBtn = document.getElementById('btn-register-submit');
  submitBtn.setAttribute('disabled', 'true');
  submitBtn.textContent = 'REGISTERING...';
  
  addLocalLog(`Registering user '${username}' on directory server...`, 'system');

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password
      })
    });
    
    const result = await response.json();
    if (response.ok && result.status === 'success') {
      addLocalLog(`Successfully registered user '${username}'. Please switch to LOGIN tab.`, 'system');
      registerForm.reset();
    } else {
      addLocalLog(`Registration failed: ${result.message || 'Unknown error'}`, 'error');
    }
  } catch (error) {
    addLocalLog(`Network failure during registration: ${error.message}`, 'error');
  } finally {
    submitBtn.removeAttribute('disabled');
    submitBtn.textContent = 'REGISTER ACCOUNT';
  }
});

// Initialize / Login Node
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  
  const submitBtn = document.getElementById('btn-login-submit');
  submitBtn.setAttribute('disabled', 'true');
  submitBtn.textContent = 'INITIALIZING I2P DAEMON...';
  
  addLocalLog(`Starting Node for '${username}'. Booting I2P Tunnel (this may take up to 2 minutes, please approve any admin/firewall prompts)...`, 'system');

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        listenPort: DEFAULT_LISTEN_PORT
      })
    });
    
    const result = await response.json();
    if (response.ok && result.status === 'success') {
      enterOnlineState(username, result.myBase32Address);
    } else {
      addLocalLog(`Initialization failed: ${result.message || 'Unknown error'}`, 'error');
      submitBtn.removeAttribute('disabled');
      submitBtn.textContent = 'LOGIN';
    }
  } catch (error) {
    addLocalLog(`Network failure during login: ${error.message}`, 'error');
    submitBtn.removeAttribute('disabled');
    submitBtn.textContent = 'LOGIN';
  }
});

function enterOnlineState(username, myBase32Address) {
  isNodeInitialized = true;
  addLocalLog(`Node connection established. Logged in as '${username}'.`, 'system');
  
  // Update UI components to online state
  authCard.style.display = 'none';
  transferCard.style.display = 'block';
  statusDot.classList.add('online');
  statusLabel.textContent = 'ONLINE';
  btnLogout.style.display = 'inline-flex';
  
  // Load Destination Address
  myAddressText.textContent = myBase32Address;
  addressBanner.style.display = 'flex';
  
  // Start polling loop
  startStatusPolling();
  loadReceivedFiles();
}

function enterOfflineState() {
  isNodeInitialized = false;
  if (statusIntervalId) clearInterval(statusIntervalId);
  statusIntervalId = null;

  // Reset UI components to offline state
  authCard.style.display = 'block';
  transferCard.style.display = 'none';
  document.getElementById('transfers-card').style.display = 'none';
  statusDot.classList.remove('online');
  statusLabel.textContent = 'OFFLINE';
  btnLogout.style.display = 'none';
  
  // Clear address banner
  addressBanner.style.display = 'none';
  myAddressText.textContent = 'not_initialized.b32.i2p';
  
  // Reset submitting buttons
  const loginSubmit = document.getElementById('btn-login-submit');
  loginSubmit.removeAttribute('disabled');
  loginSubmit.textContent = 'LOGIN';
  
  addLocalLog('Node de-initialized. Tunnels closed.', 'system');
}

btnLogout.addEventListener('click', async () => {
  if (!confirm('De-initialize active node session? This stops your receiver tunnel.')) return;
  addLocalLog('De-initializing node session...', 'system');
  try {
    const response = await fetch('/api/logout', { method: 'POST' });
    const result = await response.json();
    if (response.ok && result.status === 'success') {
      enterOfflineState();
    } else {
      addLocalLog('Logout failed: ' + (result.message || 'Unknown error'), 'error');
    }
  } catch (err) {
    addLocalLog('Network failure during logout: ' + err.message, 'error');
  }
});

// Dispatch Payload (Send File)
transferForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!selectedFile) return;

  const recipient = document.getElementById('transfer-recipient').value.trim();
  
  btnSendSubmit.setAttribute('disabled', 'true');
  btnSendSubmit.textContent = 'DISPATCHING PAYLOAD...';
  addLocalLog(`Preparing to send '${selectedFile.name}' to '${recipient}'...`, 'system');

  // Convert file to Base64 to transmit cleanly over HTTP without multi-part packages
  const reader = new FileReader();
  reader.onload = async () => {
    const base64Data = reader.result.split(',')[1];
    
    try {
      const response = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipient: recipient,
          filename: selectedFile.name,
          fileData: base64Data
        })
      });
      
      const result = await response.json();
      if (response.ok && result.status === 'success') {
        addLocalLog(`Payload '${selectedFile.name}' successfully routed and accepted by '${recipient}'.`, 'system');
        clearSelectedFile();
      } else {
        addLocalLog(`Transmission failed: ${result.message || 'Unknown error'}`, 'error');
      }
    } catch (err) {
      addLocalLog(`Transmission failed: ${err.message}`, 'error');
    } finally {
      btnSendSubmit.removeAttribute('disabled');
      btnSendSubmit.textContent = 'INITIATE SECURE STREAM';
    }
  };
  
  reader.onerror = () => {
    addLocalLog('Failed to read selected local file.', 'error');
    btnSendSubmit.removeAttribute('disabled');
    btnSendSubmit.textContent = 'INITIATE SECURE STREAM';
  };
  
  reader.readAsDataURL(selectedFile);
});

// Fetch Received Files List
async function loadReceivedFiles() {
  try {
    const response = await fetch('/api/files');
    const result = await response.json();
    if (response.ok && result.status === 'success') {
      filesTableBody.innerHTML = '';
      if (result.files.length === 0) {
        filesTableBody.innerHTML = `<tr><td colspan="3" class="text-center empty-cabinet">No files received yet.</td></tr>`;
        return;
      }
      
      result.files.forEach(file => {
        const row = document.createElement('tr');
        
        const nameCell = document.createElement('td');
        nameCell.textContent = file.name;
        nameCell.style.fontWeight = '500';
        
        const sizeCell = document.createElement('td');
        const sizeKB = file.size / 1024;
        sizeCell.textContent = sizeKB < 1024 ? `${sizeKB.toFixed(1)} KB` : `${(sizeKB / 1024).toFixed(1)} MB`;
        sizeCell.className = 'font-mono';
        
        const actionCell = document.createElement('td');
        const downloadLink = document.createElement('a');
        downloadLink.href = `/api/download?file=${encodeURIComponent(file.name)}`;
        downloadLink.className = 'btn btn-secondary btn-xs';
        downloadLink.textContent = 'GET';
        downloadLink.setAttribute('download', file.name);
        actionCell.appendChild(downloadLink);
        
        row.appendChild(nameCell);
        row.appendChild(sizeCell);
        row.appendChild(actionCell);
        filesTableBody.appendChild(row);
      });
    }
  } catch (err) {
    console.error('Failed to load cabinet files:', err);
  }
}

btnRefreshFiles.addEventListener('click', loadReceivedFiles);

// Live Logs & Status Polling Loop
function startStatusPolling() {
  if (statusIntervalId) clearInterval(statusIntervalId);
  
  statusIntervalId = setInterval(async () => {
    try {
      const response = await fetch(`/api/status?offset=${logOffset}`);
      const result = await response.json();
      
      if (response.ok && result.status === 'success') {
        // Append new console logs
        if (result.logs && result.logs.length > 0) {
          result.logs.forEach(log => {
            const line = document.createElement('div');
            // Determine type
            let logType = 'system';
            if (log.includes('[FOUT]') || log.includes('error') || log.includes('mislukt') || log.includes('failed')) {
              logType = 'error';
            }
            line.className = `log-line ${logType}-line`;
            line.textContent = log;
            consoleOutput.appendChild(line);
            logOffset++;
          });
          consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }

        // Render active transfers
        if (result.activeTransfers) {
          renderActiveTransfers(result.activeTransfers);
        }

        // Periodically refresh file list automatically if state is online
        if (result.hasNewFiles) {
          loadReceivedFiles();
        }
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  }, 1500);
}

// Clear Logs locally
btnClearLogs.addEventListener('click', () => {
  consoleOutput.innerHTML = '';
});

// Shutdown Node completely
btnShutdownNode.addEventListener('click', async () => {
  if (!confirm('Are you sure you want to terminate the application node and all tunnels?')) return;
  
  addLocalLog('Sending termination sequence to daemon...', 'system');
  if (statusIntervalId) clearInterval(statusIntervalId);
  
  try {
    await fetch('/api/shutdown', { method: 'POST' });
  } catch (e) {
    // Expected as server goes offline
  }
  
  // Update state UI
  statusDot.classList.remove('online');
  statusLabel.textContent = 'TERMINATED';
  addLocalLog('Node connection offline. Process exited.', 'system');
  btnShutdownNode.setAttribute('disabled', 'true');
});

// --- Initialization check on page load (Restores session if active) ---
async function checkCurrentStatusOnStartup() {
  try {
    const response = await fetch('/api/status?offset=0');
    const result = await response.json();
    if (response.ok && result.status === 'success') {
      if (result.username && result.myBase32Address) {
        addLocalLog('Existing node connection detected. Restoring session...', 'system');
        enterOnlineState(result.username, result.myBase32Address);
      }
    }
  } catch (e) {
    console.error('Startup status check failed:', e);
  }
}

checkCurrentStatusOnStartup();

function renderActiveTransfers(transfers) {
  const transfersCard = document.getElementById('transfers-card');
  const transfersList = document.getElementById('transfers-list');
  
  const allSends = Object.entries(transfers.sends || {});
  const allReceives = Object.entries(transfers.receives || {});
  const totalTransfersCount = allSends.length + allReceives.length;

  if (totalTransfersCount === 0) {
    transfersCard.style.display = 'none';
    return;
  }

  transfersCard.style.display = 'block';
  transfersList.innerHTML = '';

  // Render sends
  allSends.forEach(([id, t]) => {
    const item = createTransferItemHTML('UPLOAD', t.filename, t.target, t.sent, t.size, t.status, id);
    transfersList.appendChild(item);
  });

  // Render receives
  allReceives.forEach(([id, t]) => {
    const item = createTransferItemHTML('DOWNLOAD', t.filename, t.sender, t.received, t.size, t.status, id);
    transfersList.appendChild(item);
  });
}

function createTransferItemHTML(direction, filename, peer, current, total, status, id) {
  const pct = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0;
  
  const div = document.createElement('div');
  div.className = 'transfer-item';

  const directionSymbol = direction === 'UPLOAD' ? '&uarr;' : '&darr;';

  const currentFormatted = formatBytes(current);
  const totalFormatted = formatBytes(total);

  let actionsHtml = '';
  if (status === 'waiting_approval' && direction === 'DOWNLOAD') {
    actionsHtml = `
      <div class="transfer-actions" style="margin-top: 8px; display: flex; gap: 8px;">
        <button class="btn btn-primary btn-xs btn-accept" data-id="${id}" style="padding: 4px 8px; font-size: 10px;">ACCEPT</button>
        <button class="btn btn-danger btn-xs btn-decline" data-id="${id}" style="padding: 4px 8px; font-size: 10px;">DECLINE</button>
      </div>
    `;
  }

  div.innerHTML = `
    <div class="transfer-meta">
      <span class="transfer-name" title="${filename}">${directionSymbol} ${filename}</span>
      <span class="transfer-status-text ${status}">${status.replace('_', ' ').toUpperCase()}</span>
    </div>
    <div class="transfer-progress-bar ${status}">
      <div class="transfer-fill" style="width: ${pct}%"></div>
    </div>
    <div class="transfer-stats">
      <span>${direction}: ${peer}</span>
      <span>${pct}% (${currentFormatted} / ${totalFormatted})</span>
    </div>
    ${actionsHtml}
  `;

  const acceptBtn = div.querySelector('.btn-accept');
  const declineBtn = div.querySelector('.btn-decline');

  if (acceptBtn) {
    acceptBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      acceptBtn.disabled = true;
      if (declineBtn) declineBtn.disabled = true;
      acceptBtn.textContent = 'ACCEPTING...';
      try {
        const response = await fetch('/api/accept', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ transferId: id })
        });
        const result = await response.json();
        if (!response.ok || result.status !== 'success') {
          addLocalLog('Failed to accept transfer: ' + (result.message || 'Unknown error'), 'error');
        }
      } catch (err) {
        addLocalLog('Failed to accept transfer: ' + err.message, 'error');
      }
    });
  }

  if (declineBtn) {
    declineBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      declineBtn.disabled = true;
      if (acceptBtn) acceptBtn.disabled = true;
      declineBtn.textContent = 'DECLINING...';
      try {
        const response = await fetch('/api/decline', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ transferId: id })
        });
        const result = await response.json();
        if (!response.ok || result.status !== 'success') {
          addLocalLog('Failed to decline transfer: ' + (result.message || 'Unknown error'), 'error');
        }
      } catch (err) {
        addLocalLog('Failed to decline transfer: ' + err.message, 'error');
      }
    });
  }

  return div;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
