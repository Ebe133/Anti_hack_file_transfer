const net = require('net'), fs = require('fs'), path = require('path'), crypto = require('crypto'), 
  {execSync, spawn, exec} = require('child_process'), https = require('https'), http = require('http');

let TOKEN = null, UI_P = process.env.UI_PORT ? parseInt(process.env.UI_PORT, 10) : 3000,
  PUB = path.join(__dirname, 'public'), REC = process.env.RECEIVED_DIR ? path.resolve(process.env.RECEIVED_DIR) : path.join(__dirname, 'received'),
  AUTH_URL = process.env.AUTH_SERVER_URL || 'https://webgenie-ai.com/server.php';

let parsed = null;
try { parsed = new URL(AUTH_URL); } catch {}

const USE_HTTP = process.env.AUTH_USE_HTTP ? process.env.AUTH_USE_HTTP === '1' : parsed !== null,
  HOST = process.env.AUTH_HOST || (parsed ? parsed.hostname : '127.0.0.1'),
  PORT = process.env.AUTH_PORT_UI ? parseInt(process.env.AUTH_PORT_UI, 10) : (parsed ? (parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80)) : 8000),
  PATH = process.env.AUTH_PATH || (parsed ? `${parsed.pathname}${parsed.search}` : '/server.php'),
  IS_HTTPS = parsed ? parsed.protocol === 'https:' : false,
  LPORT = process.env.LISTEN_PORT ? parseInt(process.env.LISTEN_PORT, 10) : 9090,
  LOG_MAX = 500, LOG_FILE = process.env.LOG_FILE ? path.resolve(process.env.LOG_FILE) : path.join(__dirname, 'nexus.log'),
  logSt = fs.createWriteStream(LOG_FILE, {flags: 'a'});

const I2P = {samHost: process.env.I2P_SAM_HOST || '127.0.0.1', samPort: process.env.I2P_SAM_PORT ? parseInt(process.env.I2P_SAM_PORT, 10) : 7656,
  socksHost: process.env.I2P_SOCKS_HOST || '127.0.0.1', socksPort: process.env.I2P_SOCKS_PORT ? parseInt(process.env.I2P_SOCKS_PORT, 10) : 4447};

const i2p = {status: 'offline', addr: null, sock: null, sid: null, err: null};
const web = {isOn: false, user: null, i2pAddr: null, tok: null, logs: [], transfers: {send: {}, recv: {}}};

const _log = console.log.bind(console), _err = console.error.bind(console);

function log(m) {
  _log(m);
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const ln = `[${ts}] ${m}`;
  logSt.write(ln + '\n');
  web.logs.push(ln);
  if (web.logs.length > LOG_MAX) web.logs.shift();
}

console.log = log;
console.error = (m) => {
  _err(m);
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const ln = `[${ts}] [ERR] ${m}`;
  logSt.write(ln + '\n');
  web.logs.push(ln);
  if (web.logs.length > LOG_MAX) web.logs.shift();
};

const safe = (u) => String(u || '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64);
const getDir = (u) => {const s = safe(u); return s ? path.join(REC, s) : REC;};
const getCurDir = () => getDir(web.user);

const MIME = {'.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', 
  '.ico': 'image/x-icon', '.png': 'image/png', '.svg': 'image/svg+xml'};

function sendJSON(res, code, o) {
  const body = JSON.stringify(o);
  res.writeHead(code, {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store'});
  res.end(body);
}

function readBody(req, mx = 10 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let got = 0;
    req.on('data', c => {
      got += c.length;
      if (got > mx) {req.removeAllListeners('data'); reject(new Error('Payload too large')); return;}
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function serveStatic(res, fPath) {
  const ext = path.extname(fPath).toLowerCase(), mime = MIME[ext] || 'application/octet-stream';
  fs.readFile(fPath, (e, d) => {
    if (e) {res.writeHead(404); res.end('Not Found'); return;}
    res.writeHead(200, {'Content-Type': mime});
    res.end(d);
  });
}

function serveIndex(res) {
  fs.readFile(path.join(PUB, 'index.html'), 'utf8', (e, h) => {
    if (e) {res.writeHead(500); res.end('UI not found'); return;}
    const inj = h.replace('__SESSION_TOKEN_PLACEHOLDER__', TOKEN);
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
    res.end(inj);
  });
}

function connAuth(host, port, cb) {
  if (host.endsWith('.i2p')) {
    log(`[Conn] Route to ${host} via SOCKS5...`);
    connSocks5(I2P.socksHost, I2P.socksPort, host, 80, cb);
  } else {
    const h = e => cb(e), sock = net.connect({host, port: parseInt(port, 10)}, () => {
      sock.removeListener('error', h);
      cb(null, sock);
    });
    sock.on('error', h);
  }
}

function sendAuth(payload, cb, host = HOST, port = PORT) {
  if (USE_HTTP) {
    const tr = IS_HTTPS ? https : http, data = JSON.stringify(payload), primHost = host || HOST, 
      fallHost = primHost.startsWith('www.') ? primHost : `www.${primHost}`;
    let done = false, tried = false, att = 0, maxAtt = 3;
    const fin = (e, p) => {if (done) return; done = true; cb(e, p);};
    const mkReq = (hostname) => {
      att++;
      const req = tr.request({hostname, port, path: PATH, method: 'POST', 
        headers: {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), 'Accept': 'application/json'}, timeout: 8000}, 
        (res) => {
          let body = '';
          res.on('data', chunk => body += chunk.toString());
          res.on('end', () => {
            const ct = String(res.headers['content-type'] || '').toLowerCase(), tb = body.trim();
            if ((ct.includes('text/html') || tb.startsWith('<')) && (tb.includes('__test=') || tb.includes('slowAES') || tb.includes('Javascript'))) {
              fin(new Error('Auth server has anti-bot challenge'));
              return;
            }
            try {fin(null, JSON.parse(tb));} catch {fin(new Error(`Invalid JSON response (HTTP ${res.statusCode || 'n/a'})`));}
          });
        });
      req.on('timeout', () => req.destroy(new Error('ETIMEDOUT')));
      req.on('error', (e) => {
        const isDns = e && (e.code === 'ENOTFOUND' || e.code === 'EAI_AGAIN' || String(e.message || '').includes('ENOTFOUND'));
        if (!tried && isDns && hostname === primHost && fallHost !== primHost) {
          tried = true;
          log(`[Auth] DNS failed for ${primHost}. Try ${fallHost}...`);
          mkReq(fallHost);
          return;
        }
        if (att < maxAtt) {
          const dl = 500 * att;
          log(`[Auth] Net error. Retry (${att}/${maxAtt}) in ${dl}ms...`);
          setTimeout(() => mkReq(hostname), dl);
          return;
        }
        fin(e);
      });
      req.write(data);
      req.end();
    };
    mkReq(primHost);
    return;
  }

  let tcpAtt = 0, maxTcp = 3;
  const tryTcp = () => {
    tcpAtt++;
    connAuth(host, port, (e, client) => {
      if (e) {
        if (tcpAtt < maxTcp) {
          const dl = 500 * tcpAtt;
          log(`[Auth] TCP failed. Retry (${tcpAtt}/${maxTcp}) in ${dl}ms...`);
          setTimeout(tryTcp, dl);
          return;
        }
        cb(e);
        return;
      }
      client.write(JSON.stringify(payload) + '\n');
      let buf = Buffer.alloc(0), ans = false;
      client.on('data', data => {
        if (ans) return;
        buf = Buffer.concat([buf, data]);
        const nl = buf.indexOf(10);
        if (nl === -1) return;
        ans = true;
        const ln = buf.slice(0, nl).toString().trim();
        try {cb(null, JSON.parse(ln));} catch {cb(new Error('Invalid JSON response'));}
        client.destroy();
      });
      client.on('error', e => {if (ans) return; ans = true; cb(e);});
    });
  };
  tryTcp();
}

function updAddr(token, addr, cb) {
  sendAuth({action: 'update_address', session_token: token, address: addr}, (e, res) => {
    if (e) {log(`[I2P] Addr update error: ${e.message}`); if (cb) cb(e); return;}
    if (res.status === 'success') {log(`[I2P] Addr registered: ${addr}`); if (cb) cb(null);} 
    else {log(`[I2P] Addr register failed`); if (cb) cb(new Error(res.message || 'Auth err'));}
  });
}

function bootI2P() {
  i2p.status = 'starting';
  log('[I2P] Starting...');
  chkI2P((e) => {
    if (e) {i2p.status = 'error'; i2p.err = e.message; log(`[I2P] Start error: ${e.message}`); return;}
    log('[I2P] SAM detected. Init session...');
    mkSam(LPORT, (e, sid, b64, sock) => {
      if (e) {i2p.status = 'error'; i2p.err = e.message; log(`[I2P] SAM init failed`); return;}
      i2p.status = 'online';
      i2p.addr = cvt64to32(b64);
      i2p.sid = sid;
      i2p.sock = sock;
      log(`[I2P] ONLINE. Addr: ${i2p.addr}`);
      startRecv(null, null, LPORT, HOST, PORT, i2p.addr, i2p.sid, false, onIncomingUI);
      if (web.isOn && web.tok) {
        web.i2pAddr = i2p.addr;
        updAddr(web.tok, i2p.addr);
      }
    });
  });
}

if (require.main === module) startWebUI();

function login(u, p, a, host, port, cb) {
  sendAuth({action: 'login', username: u, password: p, address: a}, (e, res) => {
    if (e) return cb(new Error('Auth server error: ' + e.message));
    if (res.status === 'success') cb(null, res.session_token);
    else cb(new Error(res.message || 'Auth failed'));
  }, host, port);
}

function lookup(tok, target, host, port, cb) {
  sendAuth({action: 'lookup', session_token: tok, target}, (e, res) => {
    if (e) return cb(e);
    if (res.status === 'success') cb(null, res.address);
    else cb(new Error(res.message || 'Lookup failed'));
  }, host, port);
}

function connSocks5(host, port, thost, tport, cb) {
  const sock = net.connect({host, port}, () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
  let state = 'GREET', buf = Buffer.alloc(0);
  sock.on('data', data => {
    buf = Buffer.concat([buf, data]);
    if (state === 'GREET') {
      if (buf.length < 2) return;
      if (buf[0] !== 0x05 || buf[1] !== 0x00) {sock.destroy(); cb(new Error('SOCKS5 init failed')); return;}
      buf = buf.slice(2);
      const hb = Buffer.from(thost), req = Buffer.alloc(4 + 1 + hb.length + 2);
      req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = hb.length;
      hb.copy(req, 5);
      req.writeUInt16BE(tport, 5 + hb.length);
      state = 'CONN';
      sock.write(req);
    } else if (state === 'CONN') {
      if (buf.length < 10) return;
      if (buf[0] !== 0x05 || buf[1] !== 0x00) {sock.destroy(); cb(new Error('SOCKS5 conn failed')); return;}
      buf = buf.slice(10);
      sock.removeAllListeners('data');
      if (buf.length > 0) sock.unshift(buf);
      cb(null, sock);
    }
  });
  sock.on('error', e => cb(e));
}

function mkSam(myPort, cb) {
  const sam = net.connect({host: I2P.samHost, port: I2P.samPort}, () => sam.write('HELLO VERSION MIN=3.0 MAX=3.1\n'));
  let state = 'HELLO', buf = Buffer.alloc(0), sid = 'p2p-' + crypto.randomBytes(4).toString('hex'), b32 = null;
  sam.on('data', data => {
    buf = Buffer.concat([buf, data]);
    const nl = buf.indexOf(10);
    if (nl === -1) return;
    const ln = buf.slice(0, nl).toString().trim();
    buf = buf.slice(nl + 1);
    if (state === 'HELLO') {
      if (ln.includes('RESULT=OK')) {state = 'SESSION'; sam.write(`SESSION CREATE STYLE=STREAM DESTINATION=TRANSIENT ID=${sid}\n`);}
      else {sam.destroy(); cb(new Error('SAM handshake failed'));}
    } else if (state === 'SESSION') {
      if (ln.includes('RESULT=OK')) {state = 'LOOKUP'; sam.write('NAMING LOOKUP NAME=ME\n');}
      else {sam.destroy(); cb(new Error('SAM session create failed'));}
    } else if (state === 'LOOKUP') {
      if (ln.includes('RESULT=OK')) {
        const p = ln.split(' '), vp = p.find(x => x.startsWith('VALUE='));
        if (vp) {b32 = vp.substring(6); cb(null, sid, b32, sam);}
        else {sam.destroy(); cb(new Error('No B32 addr'));}
      } else {sam.destroy(); cb(new Error('SAM lookup failed'));}
    }
  });
  sam.on('error', e => cb(new Error('SAM conn error')));
}

function startRecv(u, tok, port, host, rport, b32, sid, mult = false, onInc = null) {
  function handle(sock) {
    log('[Recv] Inbound P2P conn accepted.');
    let done = false;
    sock.on('error', e => {if (done && (e.code === 'ECONNRESET' || e.code === 'EPIPE')) return;});
    sock.pause();
    const tval = process.env.SOCKET_TIMEOUT ? parseInt(process.env.SOCKET_TIMEOUT, 10) : 30000;
    sock.setTimeout(tval);
    sock.on('timeout', () => {log('[Recv] Timeout'); sock.destroy(); cleanup();});
    let buf = Buffer.alloc(0), state = 'SHAKE', skey = null, finfo = null, sha = null, tmp = null, ws = null, got = 0, priv = null, pub = null;
    const hsum = crypto.createHash('sha256');
    crypto.generateKeyPair('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'pkcs1', format: 'pem'}, 
      privateKeyEncoding: {type: 'pkcs1', format: 'pem'}}, (e, pubK, privK) => {
      if (e) {log('[Recv] RSA gen error'); sock.destroy(); return;}
      pub = pubK; priv = privK;
      sock.write(pub);
      sock.resume();
      sock.on('data', blk => {
        if (state === 'SHAKE' && buf.length + blk.length > 4096) {log('[Recv] Handshake buf limit'); sock.end('ERR\n'); return;}
        if (buf.length + blk.length > 256 * 1024) {log('[Recv] Stream buf limit'); sock.destroy(); return;}
        buf = Buffer.concat([buf, blk]);
        if (state === 'SHAKE') {
          if (buf.length < 8) return;
          const e1Len = buf.readUInt32BE(0), mLen = buf.readUInt32BE(4);
          if (e1Len !== 256 || mLen <= 0 || mLen > 1024) {log('[Recv] Invalid handshake'); sock.destroy(); return;}
          const pSize = 8 + e1Len + 12 + 16 + mLen;
          if (buf.length < pSize) return;
          const env1 = buf.slice(8, 8 + e1Len), nonce = buf.slice(8 + e1Len, 8 + e1Len + 12), 
            tag = buf.slice(8 + e1Len + 12, 8 + e1Len + 28), cipher = buf.slice(8 + e1Len + 28, pSize);
          buf = buf.slice(pSize);
          try {
            skey = crypto.privateDecrypt({key: priv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'}, env1);
            if (skey.length !== 32) throw new Error('Bad key len');
          } catch (e) {log('[Recv] Decrypt env1 failed'); sock.end('ERR\n'); return;}
          try {
            const dec = crypto.createDecipheriv('chacha20-poly1305', skey, nonce, {authTagLength: 16});
            dec.setAuthTag(tag);
            const meta = Buffer.concat([dec.update(cipher), dec.final()]);
            finfo = JSON.parse(meta.toString());
          } catch (e) {log('[Recv] Decrypt meta failed'); sock.end('ERR\n'); return;}
          if (!finfo.username || !finfo.filename || !finfo.file_size || !finfo.session_token) {sock.end('ERR\n'); return;}
          if (!Number.isInteger(finfo.file_size) || finfo.file_size <= 0) {log('[Recv] Bad file size'); sock.end('ERR\n'); return;}
          const vname = path.basename(finfo.filename);
          if (vname !== finfo.filename || vname.includes('..') || finfo.filename.includes('/') || finfo.filename.includes('\\') || !/^[a-zA-Z0-9_\-\. ]+$/.test(vname)) {
            log('[Recv] Unsafe name'); sock.end('ERR\n'); return;
          }
          sock.pause();
          log(`[Recv] Verify sender '${finfo.username}'...`);
          sendAuth({action: 'verify_session', session_token: finfo.session_token, username: finfo.username}, (vErr, vRes) => {
            if (vErr || !vRes || vRes.status !== 'success') {log('[Recv] Verify failed'); sock.resume(); sock.end('ERR\n'); cleanup(); return;}
            log(`[Recv] Sender verified.`);
            const isAuto = process.env.AUTO_ACCEPT === 'true';
            function doAccept() {
              log('[Recv] Accepted.');
              const od = getCurDir();
              fs.mkdirSync(od, {recursive: true});
              tmp = path.join(od, vname + '.tmp');
              try {ws = fs.createWriteStream(tmp);
                ws.on('error', e => {log('[Recv] Write error'); sock.end('ERR\n'); cleanup();});
              } catch (e) {sock.end('ERR\n'); cleanup(); return;}
              state = 'ENV2';
              sock.resume();
              sock.write('ACCEPT\n');
            }
            function doDecline() {log('[Recv] Declined.'); sock.resume(); sock.write('DECLINE\n'); sock.destroy(); cleanup();}
            if (isAuto) doAccept();
            else if (typeof onInc === 'function') onInc({username: finfo.username, filename: vname, file_size: finfo.file_size}, doAccept, doDecline);
            else doDecline();
          }, host || HOST, rport || PORT);
        } else process();
      });
    });

    function process() {
      if (state === 'ENV2') {
        if (buf.length < 4) return;
        const elen = buf.readUInt32BE(0);
        if (buf.length < 4 + elen) return;
        const env2 = buf.slice(4, 4 + elen);
        buf = buf.slice(4 + elen);
        try {
          const dec = crypto.privateDecrypt({key: priv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'}, env2);
          const ed = JSON.parse(dec.toString());
          sha = ed.sha256;
          state = 'STREAM';
          process();
        } catch (e) {log('[Recv] Env2 decrypt failed'); sock.end('ERR\n'); cleanup(); return;}
      }
      if (state === 'STREAM') {
        const CSIZE = 65536, rem = finfo.file_size - got;
        if (rem <= 0) return;
        const cchunk = Math.min(CSIZE, rem), psize = 12 + cchunk + 16;
        while (buf.length >= psize) {
          const pkt = buf.slice(0, psize);
          buf = buf.slice(psize);
          const nonce = pkt.slice(0, 12), ct = pkt.slice(12, 12 + cchunk), tag = pkt.slice(12 + cchunk, psize);
          try {
            const dec = crypto.createDecipheriv('chacha20-poly1305', skey, nonce, {authTagLength: 16});
            dec.setAuthTag(tag);
            const pt = Buffer.concat([dec.update(ct), dec.final()]);
            ws.write(pt);
            hsum.update(pt);
            got += cchunk;
          } catch (e) {log('[Recv] MAC verify failed'); sock.write('ERR\n'); sock.destroy(); cleanup(); return;}
          const nrem = finfo.file_size - got;
          if (nrem <= 0) {
            ws.end(() => {
              const fp = path.join(path.dirname(tmp), finfo.filename), csha = hsum.digest('hex');
              if (csha !== sha) {log('[Recv] SHA-256 mismatch'); sock.end('ERR\n'); cleanup();}
              else {
                fs.renameSync(tmp, fp);
                log(`[Recv] Saved: ${finfo.filename}`);
                done = true;
                sock.end(`OK\n`);
              }
            });
            break;
          }
        }
      }
    }

    function cleanup() {done = true; if (ws) ws.destroy(); if (tmp && fs.existsSync(tmp)) {try {fs.unlinkSync(tmp);} catch (e) {}}}
  }

  function startSamLoop() {
    const samA = net.connect({host: I2P.samHost, port: I2P.samPort}, () => samA.write('HELLO VERSION MIN=3.0 MAX=3.1\n'));
    let subState = 'HELLO', subBuf = Buffer.alloc(0);
    samA.on('error', e => log('[Recv] SAM error'));
    samA.on('data', data => {
      subBuf = Buffer.concat([subBuf, data]);
      while (true) {
        const nl = subBuf.indexOf(10);
        if (nl === -1) break;
        const ln = subBuf.slice(0, nl).toString().trim();
        subBuf = subBuf.slice(nl + 1);
        if (subState === 'HELLO') {
          if (ln.includes('RESULT=OK')) {subState = 'STATUS'; samA.write(`STREAM ACCEPT ID=${sid}\n`);}
          else {samA.destroy(); break;}
        } else if (subState === 'STATUS') {
          if (ln.includes('RESULT=OK')) subState = 'PEER';
          else {samA.destroy(); break;}
        } else if (subState === 'PEER') {
          log('[Recv] SAM peer connected.');
          samA.removeAllListeners('data');
          samA.removeAllListeners('error');
          if (subBuf.length > 0) samA.unshift(subBuf);
          handle(samA);
          startSamLoop();
          break;
        }
      }
    });
  }

  startSamLoop();
  log(`P2P online as '${u}' on I2P. Addr: ${b32}`);
}

function sendFile(file, tgt, myUser, token, host, port, cb) {
  let done = false;
  const fin = (e = null) => {if (done) return; done = true; if (cb) cb(e);};
  if (!fs.existsSync(file)) {fin(new Error('File not found')); return;}
  const fd = fs.readFileSync(file), fn = path.basename(file);
  log(`[Send] Lookup '${tgt}'...`);
  lookup(token, tgt, host, port, (e, taddr) => {
    if (e) {fin(e); return;}
    let connReady = (ps) => {
      log(`[Send] Connected to '${tgt}'.`);
      const tval = process.env.SOCKET_TIMEOUT ? parseInt(process.env.SOCKET_TIMEOUT, 10) : 30000;
      ps.setTimeout(tval);
      ps.on('timeout', () => {ps.destroy(); fin(new Error('Timeout'));});
      ps.on('error', (e) => {if (done && (e.code === 'ECONNRESET' || e.code === 'EPIPE')) return; fin(e);});
      let pbuf = Buffer.alloc(0), ppub = null, state = 'RSA', skey = null, ok = false, allSent = false, fail = false;
      ps.on('close', () => {if (state === 'STREAM' && (ok || (allSent && !fail))) {fin(null); return;} if (!done) fin(new Error('Conn closed'));});
      ps.on('data', blk => {
        if (pbuf.length + blk.length > 4096) {ps.destroy(); fin(new Error('Buffer limit')); return;}
        pbuf = Buffer.concat([pbuf, blk]);
        if (state === 'RSA') {
          const del = '-----END RSA PUBLIC KEY-----', didx = pbuf.indexOf(del);
          if (didx === -1) return;
          const nidx = pbuf.indexOf('\n', didx);
          if (nidx === -1) return;
          ppub = pbuf.slice(0, nidx + 1).toString();
          pbuf = pbuf.slice(nidx + 1);
          log('[Send] Got RSA key.');
          skey = crypto.randomBytes(32);
          const e1 = crypto.publicEncrypt({key: ppub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'}, skey);
          const mj = JSON.stringify({username: myUser, filename: fn, file_size: fd.length, session_token: token});
          const nonce = crypto.randomBytes(12);
          const c = crypto.createCipheriv('chacha20-poly1305', skey, nonce, {authTagLength: 16});
          const ct = Buffer.concat([c.update(Buffer.from(mj)), c.final()]);
          const tag = c.getAuthTag();
          const hdr = Buffer.alloc(8);
          hdr.writeUInt32BE(e1.length, 0);
          hdr.writeUInt32BE(ct.length, 4);
          ps.write(Buffer.concat([hdr, e1, nonce, tag, ct]));
          state = 'ACCEPT';
          log('[Send] Sent handshake.');
        } else if (state === 'ACCEPT') {
          const nl = pbuf.indexOf(10);
          if (nl === -1) return;
          const ln = pbuf.slice(0, nl).toString().trim();
          pbuf = pbuf.slice(nl + 1);
          if (ln === 'ACCEPT') {
            log('[Send] Accepted! Stream...');
            state = 'STREAM';
            const fsha = crypto.createHash('sha256').update(fd).digest('hex');
            const e2j = JSON.stringify({session_token: token, filename: fn, sha256: fsha});
            const e2 = crypto.publicEncrypt({key: ppub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'}, Buffer.from(e2j));
            const e2lb = Buffer.alloc(4);
            e2lb.writeUInt32BE(e2.length, 0);
            ps.write(e2lb);
            ps.write(e2);
            const CSIZE = 65536;
            let off = 0;
            while (off < fd.length) {
              const chunk = fd.slice(off, off + CSIZE), cn = crypto.randomBytes(12);
              const cc = crypto.createCipheriv('chacha20-poly1305', skey, cn, {authTagLength: 16});
              const cct = Buffer.concat([cc.update(chunk), cc.final()]);
              const ctag = cc.getAuthTag();
              ps.write(Buffer.concat([cn, cct, ctag]));
              off += chunk.length;
            }
            allSent = true;
            ps.end();
          } else {ps.destroy(); fin(new Error(`Declined: ${ln}`));}
        } else if (state === 'STREAM') {
          const nl = pbuf.indexOf(10);
          if (nl === -1) return;
          const ln = pbuf.slice(0, nl).toString().trim();
          if (ln.startsWith('OK')) ok = true;
          else if (ln.startsWith('ERR')) {fail = true; fin(new Error(ln));}
          ps.destroy();
        }
      });
    };
    log(`[Send] Connecting to ${taddr}...`);
    connSocks5(I2P.socksHost, I2P.socksPort, taddr, 80, (e, ps) => {
      if (e) {fin(e); return;}
      connReady(ps);
    });
  });
}

let i2pProc = null;

function cleanI2p() {
  if (i2pProc) {
    log('[I2P] Stop daemon...');
    try {i2pProc.kill();} catch (e) {}
    i2pProc = null;
  }
}

process.on('exit', cleanI2p);
process.on('SIGINT', () => {cleanI2p(); process.exit(0);});
process.on('SIGTERM', () => {cleanI2p(); process.exit(0);});

function strtI2p(exe, cb) {
  try {
    i2pProc = spawn(exe, ['--sam.enabled=1', '--sam.port=7656', '--socksproxy.enabled=1', '--socksproxy.port=4447', 
      '--httpproxy.enabled=0', '--http.enabled=0'], {detached: true, stdio: 'ignore'});
    i2pProc.unref();
    log('[I2P] Daemon started.');
    let ret = 0, maxRet = 120;
    function chkSam() {
      const s = net.connect({port: 7656, host: '127.0.0.1'}, () => {s.destroy(); log('[I2P] SAM online!'); cb(null, i2pProc);});
      s.on('error', () => {
        ret++;
        if (ret % 5 === 0) log(`[I2P] Waiting... (${ret}/${maxRet})`);
        if (ret >= maxRet) {cb(new Error(`SAM timeout`)); return;}
        setTimeout(chkSam, 1000);
      });
    }
    setTimeout(chkSam, 1000);
  } catch (e) {cb(e);}
}

function chkI2P(cb) {
  const cs = net.connect({port: 7656, host: '127.0.0.1'}, () => {
    cs.destroy();
    log('[I2P] SAM active');
    cb(null, null);
  });
  cs.on('error', () => {
    const bd = path.join(__dirname, 'bin', 'i2pd'), exe = path.join(bd, 'i2pd.exe');
    if (fs.existsSync(exe)) {
      log('[I2P] Start local i2pd...');
      strtI2p(exe, cb);
    } else {
      log('[I2P] Downloading i2pd...');
      fs.mkdirSync(bd, {recursive: true});
      const zp = path.join(bd, 'i2pd.zip'), file = fs.createWriteStream(zp);
      const url = 'https://github.com/PurpleI2P/i2pd/releases/download/2.60.0/i2pd_2.60.0_win64_mingw.zip';
      function dl(u) {
        https.get(u, (res) => {
          if (res.statusCode === 302 || res.statusCode === 301) {dl(res.headers.location); return;}
          if (res.statusCode !== 200) {cb(new Error(`Download failed`)); return;}
          res.pipe(file);
          file.on('finish', () => {
            file.close(() => {
              log('[I2P] Extracting...');
              try {
                const ezp = zp.replace(/'/g, "''"), ebd = bd.replace(/'/g, "''");
                execSync(`powershell -Command "Expand-Archive -Path '${ezp}' -DestinationPath '${ebd}' -Force"`);
                fs.unlinkSync(zp);
                const found = find(bd, 'i2pd.exe');
                if (found) {
                  if (found !== exe) fs.renameSync(found, exe);
                  log('[I2P] Installed.');
                  strtI2p(exe, cb);
                } else cb(new Error('i2pd.exe not found'));
              } catch (e) {cb(new Error(`Extract failed`));}
            });
          });
        }).on('error', (e) => {fs.unlinkSync(zp); cb(e);});
      }
      dl(url);
    }
  });
}

function find(dir, fn) {
  const fs_list = fs.readdirSync(dir);
  for (const f of fs_list) {
    const fp = path.join(dir, f), st = fs.statSync(fp);
    if (st.isDirectory()) {const r = find(fp, fn); if (r) return r;}
    else if (f.toLowerCase() === fn.toLowerCase()) return fp;
  }
}

function cvt64to32(b64) {
  const sb = b64.replace(/-/g, '+').replace(/~/g, '/'), bd = Buffer.from(sb, 'base64'), 
    h = crypto.createHash('sha256').update(bd).digest();
  const a = "abcdefghijklmnopqrstuvwxyz234567";
  let b32 = "";
  let bits = 0, val = 0;
  for (let i = 0; i < h.length; i++) {
    val = (val << 8) | h[i];
    bits += 8;
    while (bits >= 5) {b32 += a[(val >>> (bits - 5)) & 31]; bits -= 5;}
  }
  if (bits > 0) b32 += a[(val << (5 - bits)) & 31];
  return b32 + ".b32.i2p";
}

module.exports = {login, lookup, connSocks5, cvt64to32, sendFile, startRecv, chkI2P, I2P};

function onIncomingUI(info, acceptFn, declineFn) {
  if (!web.isOn) {log(`[Recv] Transfer rejected: offline.`); declineFn(); return;}
  const id = crypto.randomBytes(4).toString('hex');
  log(`[Recv] Inbound: '${info.filename}' from '${info.username}' (${(info.file_size / 1048576).toFixed(2)} MB)`);
  web.transfers.recv[id] = {filename: info.filename, sender: info.username, got: 0, size: info.file_size, status: 'waiting', acceptFn, declineFn};
}

async function handleReg(req, res) {
  let body;
  try {body = JSON.parse((await readBody(req)).toString());} catch {return sendJSON(res, 400, {status: 'error', message: 'Bad JSON'});}
  const {username, password} = body;
  if (!username || !password) return sendJSON(res, 400, {status: 'error', message: 'Required'});
  log(`[Reg] Register '${username}'...`);
  sendAuth({action: 'register', username, password}, (e, r) => {
    if (e) {return sendJSON(res, 503, {status: 'error', message: `Auth error`});}
    if (r.status === 'success') {log(`[Reg] Success`); sendJSON(res, 200, {status: 'success', message: r.message});}
    else {sendJSON(res, 400, {status: 'error', message: r.message || 'Failed'});}
  });
}

async function handleLogin(req, res) {
  if (web.isOn) return sendJSON(res, 409, {status: 'error', message: 'Node online'});
  let body;
  try {body = JSON.parse((await readBody(req)).toString());} catch {return sendJSON(res, 400, {status: 'error', message: 'Bad JSON'});}
  const {username, password} = body;
  if (!username || !password) return sendJSON(res, 400, {status: 'error', message: 'Required'});
  log(`[Login] '${username}'...`);
  login(username, password, i2p.addr || '', HOST, PORT, (e, tok) => {
    if (e) {return sendJSON(res, 503, {status: 'error', message: e.message});}
    web.isOn = true; web.user = username; web.tok = tok; web.i2pAddr = i2p.addr || null;
    log(`[Login] Online`);
    if (i2p.status === 'online') updAddr(tok, i2p.addr);
    fs.mkdirSync(getCurDir(), {recursive: true});
    sendJSON(res, 200, {status: 'success', myBase32Address: web.i2pAddr});
  });
}

async function handleSend(req, res) {
  if (!web.isOn) return sendJSON(res, 403, {status: 'error', message: 'Offline'});
  let body;
  try {body = JSON.parse((await readBody(req, Infinity)).toString());} catch {return sendJSON(res, 400, {status: 'error', message: 'Bad JSON'});}
  const {recipient, filename, fileData} = body;
  if (!recipient || !filename || !fileData) return sendJSON(res, 400, {status: 'error', message: 'Missing'});
  const sf = path.basename(filename);
  if (!sf || sf.includes('..') || !/^[a-zA-Z0-9_\-\. ]+$/.test(sf)) return sendJSON(res, 400, {status: 'error', message: 'Unsafe'});
  let fb;
  try {fb = Buffer.from(fileData, 'base64');} catch {return sendJSON(res, 400, {status: 'error', message: 'Bad Base64'});}
  const td = path.join(__dirname, 'sending_tmp');
  fs.mkdirSync(td, {recursive: true});
  const tf = path.join(td, `${Date.now()}_${sf}`);
  try {fs.writeFileSync(tf, fb);} catch (e) {return sendJSON(res, 500, {status: 'error', message: 'Write failed'});}
  const tid = crypto.randomBytes(4).toString('hex');
  web.transfers.send[tid] = {filename: sf, target: recipient, sent: 0, size: fb.length, status: 'sending'};
  log(`[Send] Start: '${sf}' → '${recipient}'...`);
  sendFile(tf, recipient, web.user, web.tok, HOST, PORT, (e) => {
    try {fs.unlinkSync(tf);} catch {}
    const t = web.transfers.send[tid];
    if (t) {t.status = e ? 'failed' : 'complete'; if (!e) t.sent = fb.length; setTimeout(() => delete web.transfers.send[tid], 10000);}
    if (e) log(`[Send] Failed`); else log(`[Send] Sent`);
  });
  sendJSON(res, 200, {status: 'success', message: `Sending`});
}

async function handleAccept(req, res) {
  let body;
  try {body = JSON.parse((await readBody(req)).toString());} catch {return sendJSON(res, 400, {status: 'error'});}
  const t = web.transfers.recv[body.transferId];
  if (!t || t.status !== 'waiting') return sendJSON(res, 404, {status: 'error'});
  log(`[Recv] Accepted`);
  t.status = 'receiving';
  t.acceptFn();
  sendJSON(res, 200, {status: 'success'});
}

async function handleDecline(req, res) {
  let body;
  try {body = JSON.parse((await readBody(req)).toString());} catch {return sendJSON(res, 400, {status: 'error'});}
  const t = web.transfers.recv[body.transferId];
  if (!t || t.status !== 'waiting') return sendJSON(res, 404, {status: 'error'});
  log(`[Recv] Declined`);
  t.declineFn();
  delete web.transfers.recv[body.transferId];
  sendJSON(res, 200, {status: 'success'});
}

async function handleLogout(req, res) {
  if (!web.isOn) return sendJSON(res, 400, {status: 'error'});
  log('[Logout] End');
  web.isOn = false; web.user = null; web.i2pAddr = null; web.tok = null; web.transfers = {send: {}, recv: {}};
  sendJSON(res, 200, {status: 'success'});
}

function handleStatus(req, res) {
  const url = new URL(req.url, `http://localhost:${UI_P}`), off = parseInt(url.searchParams.get('offset') || '0', 10);
  const nLogs = web.logs.slice(off);
  const cr = {};
  for (const [id, t] of Object.entries(web.transfers.recv)) {if (t.status !== 'waiting') cr[id] = t;}
  sendJSON(res, 200, {status: 'success', isOnline: web.isOn, username: web.user, myBase32Address: web.i2pAddr || i2p.addr, 
    i2pStatus: i2p.status, i2pError: i2p.err, logs: nLogs, activeTransfers: {sends: web.transfers.send, receives: cr}});
}

function handleFiles(req, res) {
  try {const fd = getCurDir(); const files = fs.existsSync(fd) ? fs.readdirSync(fd) : []; 
    const list = files.map(f => {const fp = path.join(fd, f); const st = fs.statSync(fp); return {name: f, size: st.size, mtime: st.mtime.toISOString()};});
    sendJSON(res, 200, {status: 'success', files: list});} catch (e) {sendJSON(res, 500, {status: 'error'});}
}

function handleDownload(req, res) {
  if (!web.isOn || !web.user) return sendJSON(res, 403, {status: 'error'});
  const url = new URL(req.url, `http://localhost:${UI_P}`), fn = url.searchParams.get('file');
  if (!fn) return sendJSON(res, 400, {status: 'error'});
  const sf = path.basename(fn);
  if (!sf || sf.includes('..') || sf !== fn || !/^[a-zA-Z0-9_\-\. ]+$/.test(sf)) return sendJSON(res, 400, {status: 'error'});
  const fp = path.join(getCurDir(), sf);
  if (!fs.existsSync(fp)) return sendJSON(res, 404, {status: 'error'});
  let st;
  try {st = fs.statSync(fp);} catch (e) {return sendJSON(res, 500, {status: 'error'});}
  res.writeHead(200, {'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${sf}"`, 'Content-Length': st.size});
  const stream = fs.createReadStream(fp);
  stream.on('error', () => {});
  stream.pipe(res);
}

function handleShutdown(req, res) {
  log('[Shutdown] Exit...');
  sendJSON(res, 200, {status: 'success'});
  if (i2p.sock) i2p.sock.destroy();
  setTimeout(() => process.exit(0), 500);
}

function startPhpSrv(cb) {
  if (USE_HTTP) {log('[PHP] Using HTTP'); cb(null); return;}
  const ts = net.connect({host: '127.0.0.1', port: PORT}, () => {ts.destroy(); log('[PHP] Running'); cb(null);});
  ts.on('error', () => {
    log('[PHP] Start server...');
    let proc;
    try {
      proc = spawn('php', ['-S', `127.0.0.1:${PORT}`, path.join(__dirname, 'server.php')], {cwd: __dirname, stdio: 'pipe'});
      let started = false;
      proc.stdout.on('data', () => {if (!started) {started = true; log('[PHP] OK'); cb(null);}});
      process.on('exit', () => {try {proc.kill();} catch {}});
    } catch (e) {cb(e);}
  });
}

function startWebUI() {
  TOKEN = crypto.randomBytes(32).toString('hex');
  logSt.write('\n' + '='.repeat(50) + '\n[App Start]\n' + '='.repeat(50) + '\n');
  startPhpSrv(() => {
    const http_srv = http.createServer(async (req, res) => {
      const tkn = req.headers['x-session-token'];
      if (tkn !== TOKEN) {res.writeHead(401); res.end('Unauthorized'); return;}
      const u = new URL(req.url, `http://localhost:${UI_P}`).pathname;
      if (u === '/') serveIndex(res);
      else if (u.startsWith('/public/')) serveStatic(res, path.join(PUB, u.slice(8)));
      else if (u === '/api/register' && req.method === 'POST') await handleReg(req, res);
      else if (u === '/api/login' && req.method === 'POST') await handleLogin(req, res);
      else if (u === '/api/send' && req.method === 'POST') await handleSend(req, res);
      else if (u === '/api/accept' && req.method === 'POST') await handleAccept(req, res);
      else if (u === '/api/decline' && req.method === 'POST') await handleDecline(req, res);
      else if (u === '/api/logout' && req.method === 'POST') await handleLogout(req, res);
      else if (u === '/api/status') handleStatus(req, res);
      else if (u === '/api/files') handleFiles(req, res);
      else if (u === '/api/download') handleDownload(req, res);
      else if (u === '/api/shutdown' && req.method === 'POST') handleShutdown(req, res);
      else {res.writeHead(404); res.end();}
    });
    http_srv.listen(UI_P, () => {
      log(`[Web] UI on http://localhost:${UI_P}`);
      bootI2P();
    });
  });
}
