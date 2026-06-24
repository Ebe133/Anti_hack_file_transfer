(() => {
  const meta = document.querySelector('meta[name="x-session-token"]');
  const TOKEN = meta ? meta.getAttribute('content') : null;
  if (!TOKEN || TOKEN === '__SESSION_TOKEN_PLACEHOLDER__' || TOKEN.length !== 64) {
    document.body.innerHTML = '';
    document.title = '';
    return;
  }
  window.__NEXUS_SESSION_TOKEN = TOKEN;
  const origFetch = window.fetch.bind(window);
  window.fetch = function(resource, options) {
    const url = typeof resource === 'string' ? resource : (resource.url || '');
    if (url.startsWith('/api/') || url.includes('127.0.0.1') || url.includes('localhost')) {
      options = options || {};
      options.headers = Object.assign({}, options.headers || {}, {'X-Session-Token': TOKEN});
    }
    return origFetch(resource, options);
  };
})();

let file = null, init = false, logOff = 0, statusInt = null, theme = localStorage.getItem('theme') || 'light';
if (theme === 'dark') {document.body.classList.add('dark-mode'); document.getElementById('btn-theme-toggle').textContent = 'LIGHT';}

const DOM = {};
['tab-login-trigger', 'tab-register-trigger', 'login-form', 'register-form', 'auth-card', 'transfer-card', 'status-dot', 'status-label',
  'address-banner-section', 'my-address-text', 'btn-copy-address', 'console-output', 'btn-clear-logs', 'btn-refresh-files', 'files-table-body',
  'file-dropzone', 'transfer-file-input', 'selected-file-details', 'selected-file-name', 'selected-file-size', 'btn-clear-file',
  'transfer-form', 'btn-send-submit', 'btn-shutdown-node', 'btn-theme-toggle', 'btn-logout', 'transfers-card', 'transfers-list',
  'loading-overlay', 'loading-status-text'].forEach(id => DOM[id] = document.getElementById(id));

document.getElementById('btn-theme-toggle').addEventListener('click', () => {
  if (document.body.classList.contains('dark-mode')) {
    document.body.classList.remove('dark-mode');
    document.getElementById('btn-theme-toggle').textContent = 'DARK';
    localStorage.setItem('theme', 'light');
  } else {
    document.body.classList.add('dark-mode');
    document.getElementById('btn-theme-toggle').textContent = 'LIGHT';
    localStorage.setItem('theme', 'dark');
  }
});

DOM['tab-login-trigger'].addEventListener('click', () => {
  DOM['tab-login-trigger'].classList.add('active');
  DOM['tab-register-trigger'].classList.remove('active');
  DOM['login-form'].style.display = 'block';
  DOM['register-form'].style.display = 'none';
});

DOM['tab-register-trigger'].addEventListener('click', () => {
  DOM['tab-register-trigger'].classList.add('active');
  DOM['tab-login-trigger'].classList.remove('active');
  DOM['register-form'].style.display = 'block';
  DOM['login-form'].style.display = 'none';
});

function log(msg, type = 'sys') {
  const line = document.createElement('div');
  line.className = `log-line ${type}-line`;
  const ts = new Date().toISOString().split('T')[1].slice(0, 8);
  line.textContent = `[${ts}] [${type.toUpperCase()}] ${msg}`;
  DOM['console-output'].appendChild(line);
  DOM['console-output'].scrollTop = DOM['console-output'].scrollHeight;
}

DOM['btn-copy-address'].addEventListener('click', () => {
  navigator.clipboard.writeText(DOM['my-address-text'].textContent).then(() => {
    const orig = DOM['btn-copy-address'].textContent;
    DOM['btn-copy-address'].textContent = 'COPIED';
    setTimeout(() => DOM['btn-copy-address'].textContent = orig, 1500);
  }).catch(e => log('Copy failed: ' + e, 'error'));
});

DOM['file-dropzone'].addEventListener('click', () => DOM['transfer-file-input'].click());
DOM['file-dropzone'].addEventListener('dragover', (e) => {e.preventDefault(); DOM['file-dropzone'].style.borderStyle = 'solid';});
DOM['file-dropzone'].addEventListener('dragleave', () => DOM['file-dropzone'].style.borderStyle = 'dashed');
DOM['file-dropzone'].addEventListener('drop', (e) => {
  e.preventDefault();
  DOM['file-dropzone'].style.borderStyle = 'dashed';
  if (e.dataTransfer.files.length > 0) selectFile(e.dataTransfer.files[0]);
});
DOM['transfer-file-input'].addEventListener('change', () => {if (DOM['transfer-file-input'].files.length > 0) selectFile(DOM['transfer-file-input'].files[0]);});

function selectFile(f) {
  const re = /^[a-zA-Z0-9_\-\. ]+$/;
  if (!re.test(f.name)) {
    log(`Bad filename: '${f.name}'`, 'error');
    alert(`Bad filename: '${f.name}'\n\nOnly letters, numbers, _, -, . allowed.`);
    clrFile();
    return;
  }
  file = f;
  DOM['selected-file-name'].textContent = f.name;
  const sizeKB = f.size / 1024;
  DOM['selected-file-size'].textContent = sizeKB < 1024 ? `${sizeKB.toFixed(1)} KB` : `${(sizeKB / 1024).toFixed(1)} MB`;
  DOM['selected-file-details'].style.display = 'flex';
  DOM['btn-send-submit'].removeAttribute('disabled');
}

DOM['btn-clear-file'].addEventListener('click', (e) => {e.stopPropagation(); clrFile();});
function clrFile() {file = null; DOM['transfer-file-input'].value = ''; DOM['selected-file-details'].style.display = 'none'; DOM['btn-send-submit'].setAttribute('disabled', 'true');}

async function dlFile(fn) {
  try {
    const res = await fetch(`/api/download?file=${encodeURIComponent(fn)}`);
    if (!res.ok) throw new Error(`Download failed (${res.status})`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fn;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    log(`Downloaded '${fn}'`, 'sys');
  } catch (e) {log(`Download failed: ${e.message}`, 'error');}
}

DOM['register-form'].addEventListener('submit', async (e) => {
  e.preventDefault();
  const u = document.getElementById('register-username').value.trim();
  const p = document.getElementById('register-password').value;
  const btn = document.getElementById('btn-register-submit');
  btn.setAttribute('disabled', 'true');
  btn.textContent = 'REGISTERING...';
  log(`Registering '${u}'...`, 'sys');
  try {
    const res = await fetch('/api/register', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p})});
    const r = await res.json();
    if (res.ok && r.status === 'success') {
      log(`Registered '${u}'. Switch to LOGIN tab.`, 'sys');
      DOM['register-form'].reset();
    } else {
      log(`Register failed: ${r.message || 'Unknown'}`, 'error');
    }
  } catch (e) {log(`Register failed: ${e.message}`, 'error');}
  btn.removeAttribute('disabled');
  btn.textContent = 'REGISTER';
});

DOM['login-form'].addEventListener('submit', async (e) => {
  e.preventDefault();
  const u = document.getElementById('login-username').value.trim();
  const p = document.getElementById('login-password').value;
  const btn = document.getElementById('btn-login-submit');
  btn.setAttribute('disabled', 'true');
  btn.textContent = 'LOGGING IN...';
  log(`Logging in '${u}'...`, 'sys');
  try {
    const res = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p, listenPort: 9090})});
    const r = await res.json();
    if (res.ok && r.status === 'success') {
      enterOnline(u, r.myBase32Address);
    } else {
      log(`Login failed: ${r.message || 'Unknown'}`, 'error');
      btn.removeAttribute('disabled');
      btn.textContent = 'LOGIN';
    }
  } catch (e) {
    log(`Login failed: ${e.message}`, 'error');
    btn.removeAttribute('disabled');
    btn.textContent = 'LOGIN';
  }
});

function enterOnline(u, addr) {
  init = true;
  log(`Node online. Logged in as '${u}'.`, 'sys');
  DOM['auth-card'].style.display = 'none';
  DOM['transfer-card'].style.display = 'block';
  DOM['status-dot'].classList.add('online');
  DOM['status-label'].textContent = 'ONLINE';
  DOM['btn-logout'].style.display = 'inline-flex';
  DOM['my-address-text'].textContent = addr || 'Starting I2P...';
  DOM['address-banner-section'].style.display = 'flex';
  startPoll();
  loadFiles();
}

function enterOffline() {
  init = false;
  DOM['auth-card'].style.display = 'block';
  DOM['transfer-card'].style.display = 'none';
  DOM['transfers-card'].style.display = 'none';
  DOM['status-dot'].classList.remove('online');
  DOM['status-label'].textContent = 'OFFLINE';
  DOM['btn-logout'].style.display = 'none';
  DOM['address-banner-section'].style.display = 'none';
  DOM['my-address-text'].textContent = 'not_online';
  const loginBtn = document.getElementById('btn-login-submit');
  loginBtn.removeAttribute('disabled');
  loginBtn.textContent = 'LOGIN';
  log('Node offline.', 'sys');
}

DOM['btn-logout'].addEventListener('click', async () => {
  if (!confirm('De-initialize node? This stops your receiver tunnel.')) return;
  log('De-initializing...', 'sys');
  try {
    const res = await fetch('/api/logout', {method: 'POST'});
    const r = await res.json();
    if (res.ok && r.status === 'success') enterOffline();
    else log('Logout failed', 'error');
  } catch (e) {log('Logout failed: ' + e.message, 'error');}
});

DOM['transfer-form'].addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!file) return;
  const recip = document.getElementById('transfer-recipient').value.trim();
  DOM['btn-send-submit'].setAttribute('disabled', 'true');
  DOM['btn-send-submit'].textContent = 'DISPATCHING...';
  log(`Sending '${file.name}' to '${recip}'...`, 'sys');
  const reader = new FileReader();
  reader.onload = async () => {
    const b64 = reader.result.split(',')[1];
    try {
      const res = await fetch('/api/send', {method: 'POST', headers: {'Content-Type': 'application/json'}, 
        body: JSON.stringify({recipient: recip, filename: file.name, fileData: b64})});
      const r = await res.json();
      if (res.ok && r.status === 'success') {
        log(r.message, 'sys');
        clrFile();
      } else {
        log(`Send failed: ${r.message || 'Unknown'}`, 'error');
      }
    } catch (e) {log(`Send failed: ${e.message}`, 'error');}
    DOM['btn-send-submit'].removeAttribute('disabled');
    DOM['btn-send-submit'].textContent = 'SEND';
  };
  reader.onerror = () => {
    log('Read file failed', 'error');
    DOM['btn-send-submit'].removeAttribute('disabled');
    DOM['btn-send-submit'].textContent = 'SEND';
  };
  reader.readAsDataURL(file);
});

async function loadFiles() {
  try {
    const res = await fetch('/api/files');
    const r = await res.json();
    if (res.ok && r.status === 'success') {
      DOM['files-table-body'].innerHTML = '';
      if (r.files.length === 0) {DOM['files-table-body'].innerHTML = '<tr><td colspan="4">No files</td></tr>';}
      r.files.forEach(f => {
        const row = DOM['files-table-body'].insertRow();
        row.innerHTML = `<td>${f.name}</td><td>${(f.size / 1024).toFixed(1)} KB</td><td>${new Date(f.mtime).toLocaleString()}</td><td><button class="btn btn-sm" onclick="dlFile('${f.name}')">Download</button></td>`;
      });
    }
  } catch (e) {console.error('Load files failed', e);}
}

DOM['btn-refresh-files'].addEventListener('click', loadFiles);

function startPoll() {
  if (statusInt) clearInterval(statusInt);
  statusInt = setInterval(async () => {
    try {
      const res = await fetch(`/api/status?offset=${logOff}`);
      const r = await res.json();
      if (res.ok && r.status === 'success') {
        if (r.logs && r.logs.length > 0) {
          r.logs.forEach(l => {
            const p = l.split('[') || [];
            const type = l.includes('[ERR]') ? 'error' : 'sys';
            DOM['console-output'].appendChild((() => {
              const d = document.createElement('div');
              d.className = `log-line ${type}-line`;
              d.textContent = l;
              return d;
            })());
          });
          DOM['console-output'].scrollTop = DOM['console-output'].scrollHeight;
          logOff += r.logs.length;
        }
        
        if (!init) return;
        if (r.isOnline !== init) {if (!r.isOnline) enterOffline();}
        if (r.myBase32Address) DOM['my-address-text'].textContent = r.myBase32Address;
        
        render(r.activeTransfers);
      }
    } catch (e) {console.error('Poll error', e);}
  }, 1500);
}

DOM['btn-clear-logs'].addEventListener('click', () => DOM['console-output'].innerHTML = '');

DOM['btn-shutdown-node'].addEventListener('click', async () => {
  if (!confirm('Terminate node and tunnels?')) return;
  log('Terminating...', 'sys');
  if (statusInt) clearInterval(statusInt);
  try {await fetch('/api/shutdown', {method: 'POST'});} catch (e) {}
  DOM['status-dot'].classList.remove('online');
  DOM['status-label'].textContent = 'TERMINATED';
  log('Node offline.', 'sys');
  DOM['btn-shutdown-node'].setAttribute('disabled', 'true');
});

async function chkStartup() {
  try {
    const res = await fetch('/api/status?offset=0');
    const r = await res.json();
    if (res.ok && r.status === 'success' && r.isOnline && r.username) {
      enterOnline(r.username, r.myBase32Address);
    }
  } catch (e) {console.error('Startup check failed', e);}
}

startPoll();
chkStartup();

function render(transfers) {
  const sends = Object.entries(transfers.sends || []);
  const recvs = Object.entries(transfers.receives || []);
  const total = sends.length + recvs.length;
  if (total === 0) {DOM['transfers-card'].style.display = 'none'; return;}
  DOM['transfers-card'].style.display = 'block';
  DOM['transfers-list'].innerHTML = '';
  
  sends.forEach(([id, t]) => {
    const pct = t.size > 0 ? Math.min(100, Math.round((t.sent / t.size) * 100)) : 0;
    const div = document.createElement('div');
    div.className = 'transfer-item';
    div.innerHTML = `
      <div class="transfer-meta">
        <span class="transfer-name" title="${t.filename}">&uarr; ${t.filename}</span>
        <span class="transfer-status-text ${t.status}">${t.status.replace('_', ' ').toUpperCase()}</span>
      </div>
      <div class="transfer-progress-bar ${t.status}"><div class="transfer-fill" style="width: ${pct}%"></div></div>
      <div class="transfer-stats">
        <span>SEND: ${t.target}</span>
        <span>${pct}% (${fmt(t.sent)} / ${fmt(t.size)})</span>
      </div>
    `;
    DOM['transfers-list'].appendChild(div);
  });
  
  recvs.forEach(([id, t]) => {
    const pct = t.size > 0 ? Math.min(100, Math.round((t.got / t.size) * 100)) : 0;
    const div = document.createElement('div');
    div.className = 'transfer-item';
    let html = `
      <div class="transfer-meta">
        <span class="transfer-name" title="${t.filename}">&darr; ${t.filename}</span>
        <span class="transfer-status-text ${t.status}">${t.status.replace('_', ' ').toUpperCase()}</span>
      </div>
      <div class="transfer-progress-bar ${t.status}"><div class="transfer-fill" style="width: ${pct}%"></div></div>
      <div class="transfer-stats">
        <span>RECV: ${t.sender}</span>
        <span>${pct}% (${fmt(t.got)} / ${fmt(t.size)})</span>
      </div>
    `;
    if (t.status === 'waiting') {
      html += `
        <div class="transfer-actions" style="margin-top: 8px; display: flex; gap: 8px;">
          <button class="btn btn-primary btn-xs" onclick="accept('${id}')">ACCEPT</button>
          <button class="btn btn-danger btn-xs" onclick="decline('${id}')">DECLINE</button>
        </div>
      `;
    }
    div.innerHTML = html;
    DOM['transfers-list'].appendChild(div);
  });
}

function fmt(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function accept(id) {
  try {
    const res = await fetch('/api/accept', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({transferId: id})});
    const r = await res.json();
    if (res.ok && r.status === 'success') log('Transfer accepted', 'sys');
    else log('Accept failed', 'error');
  } catch (e) {log('Accept failed: ' + e.message, 'error');}
}

async function decline(id) {
  try {
    const res = await fetch('/api/decline', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({transferId: id})});
    const r = await res.json();
    if (res.ok && r.status === 'success') log('Transfer declined', 'sys');
    else log('Decline failed', 'error');
  } catch (e) {log('Decline failed: ' + e.message, 'error');}
}
