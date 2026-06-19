/**
 * Day 3: Unified Secure Peer-to-Peer Node (p2p.js) - I2P & Zero-Knowledge Handshake
 * 
 * Deze node combineert client- (verzender) en server- (ontvanger) functionaliteiten.
 * - Registreert en logt in bij de centrale server.php (Zero-Knowledge, RAM-only sessies).
 * - Indien I2P is ingeschakeld, registreert de node zijn I2P Base32-adres (.b32.i2p).
 * - SOCKS5 proxy wordt gebruikt om anoniem te verbinden met I2P-destinations.
 * - SAM Bridge wordt gebruikt om anonieme stream tunnels aan te maken voor inkomende bestanden.
 * - Directe handshakes en bestandsoverdrachten zijn end-to-end gecodeerd (RSA + ChaCha20-Poly1305) 
 *   en worden volledig lokaal en autonoom afgehandeld (geen database verificatie tijdens transfers).
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, spawn, exec } = require('child_process');
const https = require('https');
const http = require('http');

// ── Web UI configuratie (direct beschikbaar voor startWebUI) ────────────────
// Per-start veiligheidstoken, geïnjecteerd in de HTML
let WEB_SESSION_TOKEN = null;

const UI_PORT = 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const RECEIVED_DIR = path.join(__dirname, 'received');
const AUTH_HOST = '127.0.0.1';
const AUTH_PORT_UI = 8000;
const LISTEN_PORT = 9090;
const LOG_MAX = 500;

// Log bestand — alle berichten worden hierheen geschreven
const LOG_FILE  = path.join(__dirname, 'nexus.log');
const logStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });

// I2P Configuratie
const I2P_CONFIG = {
  samHost: '127.0.0.1',
  samPort: 7656,            // SAM Bridge voor inkomende stream tunnels
  socksHost: '127.0.0.1',
  socksPort: 4447           // SOCKS5 proxy voor uitgaande verbindingen
};


// Start direct de Web UI bij opstarten
if (require.main === module) {
  startWebUI();
}


/**
 * Logt in bij de PHP server en registreert ons anonieme I2P adres of IP:poort.
 */
function login(username, password, address, authHost, authPort, callback) {
  const client = net.connect({ host: authHost, port: parseInt(authPort, 10) }, () => {
    client.write(JSON.stringify({
      action: 'login',
      username: username,
      password: password,
      address: address
    }) + '\n');
  });

  let buffer = Buffer.alloc(0);
  client.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    const nl = buffer.indexOf(10);
    if (nl !== -1) {
      const line = buffer.slice(0, nl).toString().trim();
      try {
        const res = JSON.parse(line);
        if (res.status === 'success') {
          callback(null, res.session_token);
        } else {
          callback(new Error(res.message));
        }
      } catch (e) {
        callback(new Error('Ongeldige JSON-reactie van server'));
      }
      client.destroy();
    }
  });

  client.on('error', err => {
    callback(new Error('Kan geen verbinding maken met authenticatieserver: ' + err.message));
  });
}

/**
 * Zoekt de I2P bestemming of IP-locatie van een online peer op.
 */
function lookup(sessionToken, targetUsername, authHost, authPort, callback) {
  const client = net.connect({ host: authHost, port: parseInt(authPort, 10) }, () => {
    client.write(JSON.stringify({
      action: 'lookup',
      session_token: sessionToken,
      target: targetUsername
    }) + '\n');
  });

  let buffer = Buffer.alloc(0);
  client.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    const nl = buffer.indexOf(10);
    if (nl !== -1) {
      const line = buffer.slice(0, nl).toString().trim();
      try {
        const res = JSON.parse(line);
        if (res.status === 'success') {
          callback(null, res.address);
        } else {
          callback(new Error(res.message));
        }
      } catch (e) {
        callback(new Error('Fout bij lookup: ' + line));
      }
      client.destroy();
    }
  });

  client.on('error', err => {
    callback(err);
  });
}

/**
 * Native SOCKS5 client om anoniem te verbinden via de I2P SOCKS5 proxy.
 */
function connectSocks5(socksHost, socksPort, targetHost, targetPort, callback) {
  const socket = net.connect({ host: socksHost, port: socksPort }, () => {
    // Stuur SOCKS5 begroeting (geen authenticatie)
    socket.write(Buffer.from([0x05, 0x01, 0x00]));
  });

  let state = 'WAITING_GREETING';
  let buffer = Buffer.alloc(0);

  socket.on('data', data => {
    buffer = Buffer.concat([buffer, data]);

    if (state === 'WAITING_GREETING') {
      if (buffer.length < 2) return;
      const ver = buffer[0];
      const method = buffer[1];
      buffer = buffer.slice(2);

      if (ver !== 0x05 || method !== 0x00) {
        socket.destroy();
        callback(new Error('SOCKS5 initialisatie mislukt.'));
        return;
      }

      // Stuur verbindingsverzoek naar I2P Destination (Domain Type 0x03)
      const hostBuf = Buffer.from(targetHost);
      const req = Buffer.alloc(4 + 1 + hostBuf.length + 2);
      req[0] = 0x05; // SOCKS5
      req[1] = 0x01; // CONNECT
      req[2] = 0x00; // Gereserveerd
      req[3] = 0x03; // Domeinnaam
      req[4] = hostBuf.length;
      hostBuf.copy(req, 5);
      req.writeUInt16BE(targetPort, 5 + hostBuf.length);

      state = 'WAITING_CONNECT';
      socket.write(req);
    } else if (state === 'WAITING_CONNECT') {
      if (buffer.length < 10) return;
      const ver = buffer[0];
      const rep = buffer[1];
      buffer = buffer.slice(10); // consummeer SOCKS5 antwoord

      if (ver !== 0x05 || rep !== 0x00) {
        socket.destroy();
        callback(new Error('SOCKS5 tunnel mislukt met code: ' + rep));
        return;
      }

      // SOCKS5 tunnel is tot stand gebracht!
      socket.removeAllListeners('data');
      if (buffer.length > 0) {
        socket.unshift(buffer);
      }
      callback(null, socket);
    }
  });

  socket.on('error', err => {
    callback(err);
  });
}

/**
 * Maakt een anonieme I2P SAM Bridge tunnel en geeft ons Base32 adres terug.
 */
function createSamSession(myPort, callback) {
  const sam = net.connect({ host: I2P_CONFIG.samHost, port: I2P_CONFIG.samPort }, () => {
    sam.write('HELLO VERSION MIN=3.0 MAX=3.1\n');
  });

  let state = 'HELLO';
  let buffer = Buffer.alloc(0);
  let sessionID = 'p2psession-' + crypto.randomBytes(4).toString('hex');
  let base32Address = null;

  sam.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    const nl = buffer.indexOf(10);
    if (nl === -1) return;

    const line = buffer.slice(0, nl).toString().trim();
    buffer = buffer.slice(nl + 1);

    if (state === 'HELLO') {
      if (line.includes('RESULT=OK')) {
        state = 'SESSION_CREATE';
        sam.write(`SESSION CREATE STYLE=STREAM DESTINATION=TRANSIENT ID=${sessionID}\n`);
      } else {
        sam.destroy();
        callback(new Error('SAM Bridge handdruk mislukt.'));
      }
    } else if (state === 'SESSION_CREATE') {
      if (line.includes('RESULT=OK')) {
        state = 'NAMELOOKUP';
        sam.write('NAMING LOOKUP NAME=ME\n');
      } else {
        sam.destroy();
        callback(new Error('Kan geen I2P-sessie aanmaken.'));
      }
    } else if (state === 'NAMELOOKUP') {
      if (line.includes('RESULT=OK')) {
        const parts = line.split(' ');
        const valuePart = parts.find(p => p.startsWith('VALUE='));
        if (valuePart) {
          base32Address = valuePart.substring(6);
          // SAM verbinding openhouden voor de sessie-instandhouding!
          callback(null, sessionID, base32Address, sam);
        } else {
          sam.destroy();
          callback(new Error('Geen Base32 adres ontvangen.'));
        }
      } else {
        sam.destroy();
        callback(new Error('SAM lookup mislukt.'));
      }
    }
  });

  sam.on('error', err => {
    callback(new Error('Fout bij verbinding met I2P SAM Bridge: ' + err.message));
  });
}

/**
 * Start de ontvanger node. Kan direct luisteren op TCP of via de I2P SAM Bridge.
 */
function startReceiver(myUsername, sessionToken, myPort, authHost, authPort, base32Address, samSessionID, isMulti = false, onIncomingTransfer = null) {
  // Functie die inkomende P2P sockets afhandelt (ongeacht TCP of I2P)
  function behandelP2PVerbinding(socket) {
    console.log('\n[P2P Ontvanger] Inkomende P2P-verbinding geaccepteerd.');

    // Beveiliging: Voorkom hangende connecties (Slowloris/inactiviteit)
    const timeoutVal = process.env.SOCKET_TIMEOUT ? parseInt(process.env.SOCKET_TIMEOUT, 10) : 30000;
    socket.setTimeout(timeoutVal);
    socket.on('timeout', () => {
      console.error('[P2P Ontvanger] Connectie gesloten wegens inactiviteit (timeout).');
      socket.destroy();
      cleanup();
    });

    // Genereer lokaal een EPHEMERAL RSA-2048 sleutelpaar per verbinding (Perfect Forward Secrecy)
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    });

    socket.on('error', err => {
      console.error('[P2P Ontvanger] Socketfout:', err.message);
    });

    // Stuur direct de openbare RSA-sleutel naar de verzender
    socket.write(publicKey);

    let buffer = Buffer.alloc(0);
    let state = 'WAITING_HANDSHAKE';
    let sessionKey = null;
    let fileInfo = null;
    let expectedSha256 = null;
    let tempPath = null;
    let writeStream = null;
    let receivedBytes = 0;

    socket.on('data', dataBlok => {
      // Beveiliging: Voorkom bufferuitputting / RAM-aanval
      if (state === 'WAITING_HANDSHAKE' && buffer.length + dataBlok.length > 4096) {
        console.error('[P2P Ontvanger] Handshake buffer limiet (4KB) overschreden. Connectie afgebroken.');
        socket.end('FOUT: Handshake buffer limiet overschreden\n');
        return;
      }

      buffer = Buffer.concat([buffer, dataBlok]);

      if (state === 'WAITING_HANDSHAKE') {
        // Handshake packet structuur:
        // [4 bytes env1Len] + [4 bytes metadataLen] + [env1] + [12 bytes nonce] + [16 bytes tag] + [encrypted metadata]
        if (buffer.length < 8) return;

        const env1Len = buffer.readUInt32BE(0);
        const metadataLen = buffer.readUInt32BE(4);

        // Beveiliging: Sanity check op de envelop- en metadatalengte om hackers direct te blokkeren
        if (env1Len !== 256 || metadataLen <= 0 || metadataLen > 1024) {
          console.error('[P2P Ontvanger] Ongeldige handshake header parameters gedetecteerd. Connectie direct verbroken.');
          socket.destroy();
          return;
        }

        const packetSize = 8 + env1Len + 12 + 16 + metadataLen;

        if (buffer.length < packetSize) return;

        const envelope1 = buffer.slice(8, 8 + env1Len);
        const nonce = buffer.slice(8 + env1Len, 8 + env1Len + 12);
        const tag = buffer.slice(8 + env1Len + 12, 8 + env1Len + 28);
        const ciphertext = buffer.slice(8 + env1Len + 28, packetSize);

        // Haal restant uit buffer
        buffer = buffer.slice(packetSize);

        // 1. Decrypt 1e envelop om ChaCha20-Poly1305 sleutel te herstellen
        try {
          sessionKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
          }, envelope1);

          if (sessionKey.length !== 32) throw new Error('Foutieve symmetrische sleutellengte');
        } catch (err) {
          console.error('[P2P Ontvanger] Decryptie van 1e envelop mislukt:', err.message);
          socket.end('FOUT: RSA decodering mislukt\n');
          return;
        }

        // 2. Decrypt de metadata handshake met ChaCha20-Poly1305
        try {
          const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
          decipher.setAuthTag(tag);
          const decryptedMetadata = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

          fileInfo = JSON.parse(decryptedMetadata.toString());
        } catch (err) {
          console.error('[P2P Ontvanger] Decryptie van metadata handshake mislukt:', err.message);
          socket.end('FOUT: Metadata handdruk corrupt\n');
          return;
        }

        if (!fileInfo.username || !fileInfo.filename || !fileInfo.file_size) {
          socket.end('FOUT: Incomplete metadata\n');
          return;
        }

        // Beveiliging: Limiteer bestandsgrootte tot max 500MB
        const MAX_FILE_SIZE = 500 * 1024 * 1024;
        if (fileInfo.file_size > MAX_FILE_SIZE) {
          console.error(`[P2P Ontvanger] Bestand te groot: ${fileInfo.file_size} bytes (Max: 500MB)`);
          socket.end('FOUT: Bestand te groot (max 500MB)\n');
          return;
        }

        // Beveiliging: Directory traversal check (mag geen padtekens bevatten)
        const veiligeNaam = path.basename(fileInfo.filename);
        if (veiligeNaam !== fileInfo.filename || veiligeNaam.includes('..') ||
          fileInfo.filename.includes('/') || fileInfo.filename.includes('\\')) {
          console.error(`[P2P Ontvanger] Directory traversal gedetecteerd: ${fileInfo.filename}`);
          socket.end('FOUT: Onveilige bestandsnaam/pad\n');
          return;
        }

        // Beveiliging: Vraag toestemming via callback (UI) of via console
        const isAutoAccept = process.env.AUTO_ACCEPT === 'true';

        // Helper: schrijf het bestand en start ontvangst
        function doAccept() {
          console.log('[P2P Ontvanger] Overdracht geaccepteerd. Start download...');
          const ontvangMap = path.join(__dirname, 'received');
          fs.mkdirSync(ontvangMap, { recursive: true });
          tempPath = path.join(ontvangMap, veiligeNaam + '.tmp');

          writeStream = fs.createWriteStream(tempPath);
          writeStream.on('error', err => {
            console.error('[P2P Ontvanger] Bestandsfout:', err.message);
            socket.end('FOUT: Server schrijf error\n');
            cleanup();
          });

          state = 'WAITING_ENVELOPE_2';
          socket.resume();
          socket.write('ACCEPT\n');
          processPayload();
        }

        function doDecline() {
          console.log('[P2P Ontvanger] Overdracht geweigerd.');
          socket.write('DECLINE: Geweigerd door ontvanger\n');
          socket.destroy();
          cleanup();
        }

        if (isAutoAccept) {
          console.log('[P2P Ontvanger] AUTO_ACCEPT actief. Overdracht automatisch geaccepteerd.');
          doAccept();
        } else if (typeof onIncomingTransfer === 'function') {
          // UI-modus: pauzeer en geef controle aan de Web UI callback
          socket.pause();
          console.log(`[P2P Ontvanger] Wachten op UI-beslissing voor '${veiligeNaam}'...`);
          onIncomingTransfer(
            { username: fileInfo.username, filename: veiligeNaam, file_size: fileInfo.file_size },
            doAccept,
            doDecline
          );
        } else {
          // Geen callback en geen AUTO_ACCEPT: automatisch weigeren
          console.log('[P2P Ontvanger] Geen UI callback beschikbaar. Transfer geweigerd.');
          doDecline();
        }
      } else {
        processPayload();
      }
    });

    function processPayload() {
      if (state === 'WAITING_ENVELOPE_2') {
        if (buffer.length < 4) return;
        const envLen = buffer.readUInt32BE(0);
        if (buffer.length < 4 + envLen) return;

        const envelope2Bin = buffer.slice(4, 4 + envLen);
        buffer = buffer.slice(4 + envLen);

        // Decrypt 2e envelop met onze RSA Private Key
        try {
          const decryptedEnv = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
          }, envelope2Bin);

          const envData = JSON.parse(decryptedEnv.toString());
          expectedSha256 = envData.sha256;
          console.log(`[P2P Ontvanger] 2e Envelop ontsleuteld. Verwachte hash: ${expectedSha256}`);
          state = 'STREAMING';
        } catch (err) {
          console.error('[P2P Ontvanger] Decryptie van 2e envelop mislukt:', err.message);
          socket.end('FOUT: 2e envelop corrupt\n');
          cleanup();
          return;
        }
      }

      if (state === 'STREAMING') {
        const CHUNK_SIZE = 65536;
        const remaining = fileInfo.file_size - receivedBytes;
        if (remaining <= 0) return;

        const currentChunk = Math.min(CHUNK_SIZE, remaining);
        const packetSize = 12 + currentChunk + 16; // nonce + ciphertext + tag

        while (buffer.length >= packetSize) {
          const packet = buffer.slice(0, packetSize);
          buffer = buffer.slice(packetSize);

          const nonce = packet.slice(0, 12);
          const ciphertext = packet.slice(12, 12 + currentChunk);
          const tag = packet.slice(12 + currentChunk, packetSize);

          try {
            const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
            decipher.setAuthTag(tag);
            const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

            writeStream.write(plaintext);
            receivedBytes += currentChunk;
          } catch (err) {
            console.error('[P2P Ontvanger] Poly1305 MAC verificatie mislukt! Data is corrupt.');
            socket.write('FOUT: Integriteitsfout tijdens streaming.\n');
            socket.destroy();
            cleanup();
            return;
          }

          const nextRemaining = fileInfo.file_size - receivedBytes;
          if (nextRemaining <= 0) {
            writeStream.end(() => {
              const finalPath = path.join(path.dirname(tempPath), fileInfo.filename);
              const calculatedSha256 = crypto.createHash('sha256').update(fs.readFileSync(tempPath)).digest('hex');

              if (calculatedSha256 !== expectedSha256) {
                console.error('[P2P Ontvanger] SHA-256 integriteitscontrole mislukt!');
                socket.write('FOUT: SHA-256 hash mismatch.\n');
                socket.destroy();
                cleanup();
              } else {
                fs.renameSync(tempPath, finalPath);
                console.log(`[P2P Ontvanger] Bestand succesvol opgeslagen: ${fileInfo.filename}`);
                socket.write(`OK geupload: ${fileInfo.filename}\n`);
                socket.destroy();
                if (isMulti) {
                  process.stdout.write('\n> ');
                }
              }
            });
            break;
          }
        }
      }
    }

    function cleanup() {
      if (writeStream) writeStream.destroy();
      if (tempPath && fs.existsSync(tempPath)) {
        try { fs.unlinkSync(tempPath); } catch (e) { }
      }
    }
  }

  // Luister via I2P SAM Bridge
  function startSamAcceptLoop() {
    const samAccept = net.connect({ host: I2P_CONFIG.samHost, port: I2P_CONFIG.samPort }, () => {
      samAccept.write('HELLO VERSION MIN=3.0 MAX=3.1\n');
    });

    let subState = 'HELLO';
    let subBuffer = Buffer.alloc(0);

    samAccept.on('error', err => {
      console.error('[P2P Ontvanger] I2P accept socket fout:', err.message);
    });

    samAccept.on('data', data => {
      subBuffer = Buffer.concat([subBuffer, data]);

      while (true) {
        const nl = subBuffer.indexOf(10);
        if (nl === -1) break;
        const line = subBuffer.slice(0, nl).toString().trim();
        subBuffer = subBuffer.slice(nl + 1);

        if (subState === 'HELLO') {
          if (line.includes('RESULT=OK')) {
            subState = 'STREAM_STATUS';
            samAccept.write(`STREAM ACCEPT ID=${samSessionID}\n`);
          } else {
            console.error('[P2P Ontvanger] I2P HELLO mislukt:', line);
            samAccept.destroy();
            break;
          }
        } else if (subState === 'STREAM_STATUS') {
          if (line.includes('RESULT=OK')) {
            subState = 'PEER_CONNECTION';
            // Tunnel luistert nu. We wachten tot de peer verbinding maakt.
          } else {
            console.error('[P2P Ontvanger] I2P Accept status mislukt:', line);
            samAccept.destroy();
            break;
          }
        } else if (subState === 'PEER_CONNECTION') {
          console.log('[P2P Ontvanger] I2P SAM tunnel peer verbonden. Handshake starten...');

          // Deze socket is nu verbonden met de client!
          samAccept.removeAllListeners('data');
          if (subBuffer.length > 0) {
            samAccept.unshift(subBuffer);
          }
          behandelP2PVerbinding(samAccept);

          // Start direct de volgende accept socket om meer verbindingen op te vangen
          startSamAcceptLoop();
          break;
        }
      }
    });
  }

  startSamAcceptLoop();
  console.log(`P2P Node is online als '${myUsername}' op I2P.`);
  console.log(`I2P Destination: ${base32Address}`);
}

/**
 * Maakt verbinding met een peer en verzendt een bestand.
 */
function performSendFlow(file, targetUsername, myUsername, sessionToken, authHost, authPort, callback) {
  if (!fs.existsSync(file)) {
    console.error(`Fout: Bestand '${file}' bestaat niet.`);
    if (callback) callback();
    return;
  }
  const fileData = fs.readFileSync(file);
  const filename = path.basename(file);

  console.log(`[P2P Verzender] Vraag adres op van '${targetUsername}'...`);
  lookup(sessionToken, targetUsername, authHost, authPort, (err, targetAddress) => {
    if (err) {
      console.error(`[P2P Verzender] Lookup mislukt:`, err.message);
      if (callback) callback();
      return;
    }

    let verbindingKlaar = (peerSocket) => {
      console.log(`[P2P Verzender] Verbonden met peer '${targetUsername}'. Wachten op RSA sleutel...`);

      const timeoutVal = process.env.SOCKET_TIMEOUT ? parseInt(process.env.SOCKET_TIMEOUT, 10) : 30000;
      peerSocket.setTimeout(timeoutVal);
      peerSocket.on('timeout', () => {
        console.error('[P2P Verzender] Verbinding gesloten wegens time-out.');
        peerSocket.destroy();
        if (callback) callback();
      });

      let peerBuffer = Buffer.alloc(0);
      let peerPublicKey = null;
      let state = 'WAITING_RSA';
      let sessionKey = null;

      peerSocket.on('data', dataBlok => {
        peerBuffer = Buffer.concat([peerBuffer, dataBlok]);

        if (state === 'WAITING_RSA') {
          const delimiter = '-----END RSA PUBLIC KEY-----';
          const delimiterIndex = peerBuffer.indexOf(delimiter);
          if (delimiterIndex === -1) return;

          const nlIndex = peerBuffer.indexOf('\n', delimiterIndex);
          if (nlIndex === -1) return;

          // Extraheer de RSA Public Key van de ontvanger (inclusief newline)
          peerPublicKey = peerBuffer.slice(0, nlIndex + 1).toString();
          peerBuffer = peerBuffer.slice(nlIndex + 1);
          console.log('[P2P Verzender] RSA Public Key ontvangen van peer.');

          // Genereer 32-byte symmetrische sleutel
          sessionKey = crypto.randomBytes(32);

          // Encrypt symmetrische sleutel (1e envelop)
          const envelope1 = crypto.publicEncrypt({
            key: peerPublicKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
          }, sessionKey);

          // Encrypt metadata met ChaCha20-Poly1305
          const metadataJSON = JSON.stringify({
            username: myUsername,
            filename: filename,
            file_size: fileData.length
          });
          const nonce = crypto.randomBytes(12);
          const cipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
          const ciphertext = Buffer.concat([cipher.update(Buffer.from(metadataJSON)), cipher.final()]);
          const tag = cipher.getAuthTag();

          // Verzend: [4b env1Len] + [env1] + [4b metadataLen] + [12b nonce] + [16b tag] + [ciphertext]
          const header = Buffer.alloc(8);
          header.writeUInt32BE(envelope1.length, 0);
          header.writeUInt32BE(ciphertext.length, 4);

          peerSocket.write(Buffer.concat([header, envelope1, nonce, tag, ciphertext]));
          state = 'WAITING_ACCEPT';
          console.log('[P2P Verzender] Gecodeerde metadata handshake verzonden. Wachten op acceptatie...');
        } else if (state === 'WAITING_ACCEPT') {
          const nl = peerBuffer.indexOf(10);
          if (nl === -1) return;

          const line = peerBuffer.slice(0, nl).toString().trim();
          peerBuffer = peerBuffer.slice(nl + 1);

          if (line === 'ACCEPT') {
            console.log('[P2P Verzender] Overdracht geaccepteerd! Start payload streaming...');
            state = 'STREAMING';

            const fileSha256 = crypto.createHash('sha256').update(fileData).digest('hex');

            // Maak en versleutel de 2e envelop
            const envelope2JSON = JSON.stringify({
              session_token: sessionToken,
              filename: filename,
              sha256: fileSha256
            });
            const envelope2 = crypto.publicEncrypt({
              key: peerPublicKey,
              padding: crypto.constants.RSA_PKCS1_PADDING
            }, Buffer.from(envelope2JSON));

            // Stuur [4b env2Len] + [envelope2]
            const env2LenBuf = Buffer.alloc(4);
            env2LenBuf.writeUInt32BE(envelope2.length, 0);
            peerSocket.write(env2LenBuf);
            peerSocket.write(envelope2);

            // Stream chunks
            const CHUNK_SIZE = 65536;
            let offset = 0;
            while (offset < fileData.length) {
              const chunk = fileData.slice(offset, offset + CHUNK_SIZE);
              const chunkNonce = crypto.randomBytes(12);

              const chunkCipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, chunkNonce, { authTagLength: 16 });
              const chunkCiphertext = Buffer.concat([chunkCipher.update(chunk), chunkCipher.final()]);
              const chunkTag = chunkCipher.getAuthTag();

              peerSocket.write(Buffer.concat([chunkNonce, chunkCiphertext, chunkTag]));
              offset += chunk.length;
            }
            peerSocket.end();
          } else {
            console.error('[P2P Verzender] Overdracht geweigerd:', line);
            peerSocket.destroy();
            if (callback) callback();
          }
        } else if (state === 'STREAMING') {
          const nl = peerBuffer.indexOf(10);
          if (nl === -1) return;
          const line = peerBuffer.slice(0, nl).toString().trim();
          console.log('[P2P Verzender] Peer antwoord:', line);
          peerSocket.destroy();
          if (callback) callback();
        }
      });
    };

    console.log(`[P2P Verzender] Maak anonieme verbinding via SOCKS5 proxy naar ${targetAddress}...`);
    connectSocks5(I2P_CONFIG.socksHost, I2P_CONFIG.socksPort, targetAddress, 80, (socksErr, peerSocket) => {
      if (socksErr) {
        console.error('[P2P Verzender] Kan niet verbinden via SOCKS5:', socksErr.message);
        if (callback) callback();
        return;
      }
      verbindingKlaar(peerSocket);
    });
  });
}

/**
 * Start node in receive modus.
 */
function initI2PAndLogin(myPort, username, password, authHost, authPort, callback) {
  checkAndInstallI2P((i2pErr) => {
    if (i2pErr) {
      return callback(new Error(`Automatische I2P-opstart of download mislukt: ${i2pErr.message}`));
    }

    console.log('Maak verbinding met I2P SAM Bridge...');
    createSamSession(myPort, (err, sessionID, base64Destination, samSocket) => {
      if (err) {
        return callback(new Error(`SAM Bridge niet gedetecteerd of verbinding mislukt: ${err.message}`));
      }

      const myBase32Address = convertI2PBase64toBase32(base64Destination);

      console.log('Inloggen bij directory server...');
      login(username, password, myBase32Address, authHost, authPort, (loginErr, sessionToken) => {
        if (loginErr) {
          samSocket.destroy();
          return callback(loginErr);
        }
        callback(null, { sessionToken, myBase32Address, sessionID, samSocket });
      });
    });
  });
}


let i2pChildProcess = null;

// Ruim het I2P-achtergrondproces op bij het afsluiten van Node
function cleanupI2p() {
  if (i2pChildProcess) {
    console.log('[I2P Manager] Stoppen van lokale i2pd daemon...');
    try {
      i2pChildProcess.kill();
    } catch (e) { }
    i2pChildProcess = null;
  }
}

process.on('exit', cleanupI2p);
process.on('SIGINT', () => {
  cleanupI2p();
  process.exit(0);
});
process.on('SIGTERM', () => {
  cleanupI2p();
  process.exit(0);
});

function startI2pProcess(exePath, callback) {
  try {
    i2pChildProcess = spawn(exePath, [
      '--sam.enabled=1',
      '--sam.port=7656',
      '--socksproxy.enabled=1',
      '--socksproxy.port=4447',
      '--httpproxy.enabled=0',
      '--http.enabled=0'
    ], {
      detached: true,
      stdio: 'ignore'
    });

    i2pChildProcess.unref();

    console.log('[I2P Manager] i2pd daemon gestart in achtergrond. Wachten tot SAM Bridge online komt...');

    let retries = 0;
    const maxRetries = 120; // 120 seconden wachttijd (genoeg voor UAC / admin bevoegdheid verlenen)

    function checkSamOnline() {
      const socket = net.connect({ port: 7656, host: '127.0.0.1' }, () => {
        socket.destroy();
        console.log('[I2P Manager] SAM Bridge is online gekomen en luistert!');
        callback(null, i2pChildProcess);
      });

      socket.on('error', () => {
        retries++;
        if (retries % 5 === 0) {
          console.log(`[I2P Manager] Wachten tot SAM Bridge online komt... (poging ${retries}/${maxRetries})`);
        }
        if (retries >= maxRetries) {
          callback(new Error(`SAM Bridge startte niet op binnen de verwachte tijd (${maxRetries}s).`));
          return;
        }
        setTimeout(checkSamOnline, 1000);
      });
    }

    setTimeout(checkSamOnline, 1000);
  } catch (err) {
    callback(err);
  }
}

function checkAndInstallI2P(callback) {
  // Eerst testen of SAM Bridge al online is (poort 7656)
  const checkSocket = net.connect({ port: 7656, host: '127.0.0.1' }, () => {
    checkSocket.destroy();
    console.log('[I2P Manager] SAM Bridge is al actief op poort 7656.');
    callback(null, null); // Reeds actief
  });

  checkSocket.on('error', () => {
    // SAM Bridge is offline, we moeten kijken of we i2pd lokaal hebben
    const binDir = path.join(__dirname, 'bin', 'i2pd');
    const exePath = path.join(binDir, 'i2pd.exe');

    if (fs.existsSync(exePath)) {
      console.log('[I2P Manager] SAM Bridge offline, maar lokale i2pd.exe gevonden. Starten...');
      startI2pProcess(exePath, callback);
    } else {
      console.log('[I2P Manager] SAM Bridge offline en geen lokale i2pd.exe gevonden.');
      console.log('[I2P Manager] Downloaden van portable PurpleI2P i2pd (v2.60.0) voor Windows...');

      fs.mkdirSync(binDir, { recursive: true });
      const zipPath = path.join(binDir, 'i2pd.zip');
      const file = fs.createWriteStream(zipPath);

      const downloadUrl = 'https://github.com/PurpleI2P/i2pd/releases/download/2.60.0/i2pd_2.60.0_win64_mingw.zip';

      function downloadFile(url) {
        https.get(url, (response) => {
          if (response.statusCode === 302 || response.statusCode === 301) {
            downloadFile(response.headers.location);
            return;
          }
          if (response.statusCode !== 200) {
            callback(new Error(`Download mislukt met statuscode ${response.statusCode}`));
            return;
          }
          response.pipe(file);
          file.on('finish', () => {
            file.close(() => {
              console.log('[I2P Manager] Download voltooid. Uitpakken van ZIP via PowerShell...');
              try {
                // Uitpakken met PowerShell Expand-Archive
                execSync(`powershell -Command "Expand-Archive -Path '${zipPath}' -DestinationPath '${binDir}' -Force"`);
                fs.unlinkSync(zipPath); // Verwijder de ZIP

                // Zoek recursief naar i2pd.exe (in het geval van een geneste ZIP structuur)
                const foundExe = findFileRecursively(binDir, 'i2pd.exe');
                if (foundExe) {
                  if (foundExe !== exePath) {
                    fs.renameSync(foundExe, exePath);
                  }
                  console.log('[I2P Manager] Lokale i2pd succesvol geïnstalleerd. Starten...');
                  startI2pProcess(exePath, callback);
                } else {
                  callback(new Error('i2pd.exe niet gevonden na het uitpakken van de ZIP.'));
                }
              } catch (extractErr) {
                callback(new Error(`Fout bij uitpakken van ZIP: ${extractErr.message}`));
              }
            });
          });
        }).on('error', (err) => {
          fs.unlinkSync(zipPath);
          callback(err);
        });
      }

      downloadFile(downloadUrl);
    }
  });
}

function findFileRecursively(dir, filename) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      const res = findFileRecursively(fullPath, filename);
      if (res) return res;
    } else if (file.toLowerCase() === filename.toLowerCase()) {
      return fullPath;
    }
  }
}

function convertI2PBase64toBase32(base64Destination) {
  const sanitizedBase64 = base64Destination.replace(/-/g, '+').replace(/~/g, '/');
  const binaryData = Buffer.from(sanitizedBase64, 'base64');
  const hash = crypto.createHash('sha256').update(binaryData).digest();

  const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let base32String = "";

  let bits = 0;
  let value = 0;
  for (let i = 0; i < hash.length; i++) {
    value = (value << 8) | hash[i];
    bits += 8;
    while (bits >= 5) {
      base32String += base32Alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    base32String += base32Alphabet[(value << (5 - bits)) & 31];
  }

  return base32String + ".b32.i2p";
}

module.exports = {
  login,
  lookup,
  connectSocks5,
  convertI2PBase64toBase32,
  performSendFlow,
  initI2PAndLogin,
  startReceiver,
  checkAndInstallI2P,
  I2P_CONFIG
};

// ═══════════════════════════════════════════════════════════════════════════
// WEB UI — Ingebouwde HTTP Server
// ═══════════════════════════════════════════════════════════════════════════

// App state (RAM-only)
const webState = {
  isOnline: false,
  username: null,
  myBase32Address: null,
  authToken: null,
  samSocket: null,
  hasNewFiles: false,
  logs: [],
  activeTransfers: { sends: {}, receives: {} },
};

// Sla originele console op vóór enige patching — voorkomt recursie in webLog
const _origConsoleLog = console.log.bind(console);
const _origConsoleErr = console.error.bind(console);

function webLog(msg) {

  const ts   = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const line = `[${ts}] ${msg}`;
  _origConsoleLog(line);              // altijd origineel gebruiken
  logStream.write(line + '\n');      // schrijf naar nexus.log
  webState.logs.push(line);
  if (webState.logs.length > LOG_MAX) webState.logs.shift();
}

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

function serveStaticFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not Found'); return; }
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

function serveIndex(res) {
  fs.readFile(path.join(PUBLIC_DIR, 'index.html'), 'utf8', (err, html) => {
    if (err) { res.writeHead(500); res.end('UI niet gevonden. Controleer of de public/ map aanwezig is.'); return; }
    // Injecteer het session token in de <meta> placeholder
    const injected = html.replace('__SESSION_TOKEN_PLACEHOLDER__', WEB_SESSION_TOKEN);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(injected);
  });
}

// Patch console.log/error tijdelijk naar webLog en herstel nadien
function withWebLog(fn, callback) {
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args) => webLog(args.join(' '));
  console.error = (...args) => webLog('[FOUT] ' + args.join(' '));
  fn(() => {
    console.log = origLog;
    console.error = origErr;
    if (callback) callback();
  });
}

// ── Inkomende transfer UI callback ───────────────────────────────────────────
function onIncomingTransferUI(info, acceptFn, declineFn) {
  const id = crypto.randomBytes(4).toString('hex');
  webLog(`[Ontvanger] Inkomend: '${info.filename}' van '${info.username}' (${(info.file_size / 1048576).toFixed(2)} MB) — wacht op UI-beslissing...`);
  webState.activeTransfers.receives[id] = {
    filename: info.filename,
    sender: info.username,
    received: 0,
    size: info.file_size,
    status: 'waiting_approval',
    acceptFn,
    declineFn,
  };
}

// ── API handlers ─────────────────────────────────────────────────────────────

async function handleWebRegister(req, res) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON verzoek.' }); }

  const { username, password } = body;
  if (!username || !password)
    return sendJSON(res, 400, { status: 'error', message: 'Gebruikersnaam en wachtwoord verplicht.' });

  webLog(`[Register] Registreren van '${username}'...`);

  const client = net.connect({ host: AUTH_HOST, port: AUTH_PORT_UI }, () => {
    client.write(JSON.stringify({ action: 'register', username, password }) + '\n');
  });

  let answered = false;
  client.on('data', data => {
    if (answered) return; answered = true;
    try {
      const r = JSON.parse(data.toString().trim());
      if (r.status === 'success') {
        webLog(`[Register] Succes: '${username}' aangemaakt.`);
        sendJSON(res, 200, { status: 'success', message: r.message });
      } else {
        webLog(`[Register] Mislukt: ${r.message}`);
        sendJSON(res, 400, { status: 'error', message: r.message });
      }
    } catch { sendJSON(res, 500, { status: 'error', message: 'Ongeldig antwoord van auth server.' }); }
    client.destroy();
  });
  client.on('error', err => {
    if (answered) return; answered = true;
    webLog(`[Register] Netwerkfout: ${err.message}`);
    sendJSON(res, 503, { status: 'error', message: `Kan niet verbinden met auth server: ${err.message}` });
  });
  setTimeout(() => {
    if (!answered) {
      answered = true; client.destroy();
      sendJSON(res, 504, { status: 'error', message: 'Auth server timeout.' });
    }
  }, 10000);
}

async function handleWebLogin(req, res) {
  if (webState.isOnline)
    return sendJSON(res, 409, { status: 'error', message: 'Node is al actief. Log eerst uit.' });

  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON verzoek.' }); }

  const { username, password } = body;
  if (!username || !password)
    return sendJSON(res, 400, { status: 'error', message: 'Gebruikersnaam en wachtwoord verplicht.' });

  webLog(`[Login] I2P opstarten en inloggen als '${username}'...`);

  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a) => webLog(a.join(' '));
  console.error = (...a) => webLog('[FOUT] ' + a.join(' '));

  initI2PAndLogin(LISTEN_PORT, username, password, AUTH_HOST, AUTH_PORT_UI, (err, info) => {
    console.log = origLog;
    console.error = origErr;

    if (err) {
      webLog(`[Login] Mislukt: ${err.message}`);
      return sendJSON(res, 503, { status: 'error', message: err.message });
    }

    webState.isOnline = true;
    webState.username = username;
    webState.myBase32Address = info.myBase32Address;
    webState.authToken = info.sessionToken;
    webState.samSocket = info.samSocket;

    webLog(`[Login] Online als '${username}'. I2P: ${info.myBase32Address}`);

    const origLog2 = console.log;
    const origErr2 = console.error;
    console.log = (...a) => webLog(a.join(' '));
    console.error = (...a) => webLog('[FOUT] ' + a.join(' '));

    startReceiver(
      username, info.sessionToken, LISTEN_PORT,
      AUTH_HOST, AUTH_PORT_UI,
      info.myBase32Address, info.sessionID,
      false, onIncomingTransferUI
    );

    console.log = origLog2;
    console.error = origErr2;

    fs.mkdirSync(RECEIVED_DIR, { recursive: true });
    sendJSON(res, 200, { status: 'success', myBase32Address: info.myBase32Address });
  });
}

async function handleWebSend(req, res) {
  if (!webState.isOnline)
    return sendJSON(res, 403, { status: 'error', message: 'Node is niet actief. Log eerst in.' });

  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON verzoek.' }); }

  const { recipient, filename, fileData } = body;
  if (!recipient || !filename || !fileData)
    return sendJSON(res, 400, { status: 'error', message: 'Ontbrekende velden: recipient, filename, fileData.' });

  const safeFilename = path.basename(filename);
  if (!safeFilename || safeFilename.includes('..'))
    return sendJSON(res, 400, { status: 'error', message: 'Onveilige bestandsnaam.' });

  let fileBuffer;
  try { fileBuffer = Buffer.from(fileData, 'base64'); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldige Base64 data.' }); }

  if (fileBuffer.length > 500 * 1024 * 1024)
    return sendJSON(res, 413, { status: 'error', message: 'Bestand te groot (max 500MB).' });

  const tmpDir = path.join(__dirname, 'sending_tmp');
  fs.mkdirSync(tmpDir, { recursive: true });
  const tmpFile = path.join(tmpDir, `${Date.now()}_${safeFilename}`);
  fs.writeFileSync(tmpFile, fileBuffer);

  const tid = crypto.randomBytes(4).toString('hex');
  webState.activeTransfers.sends[tid] = {
    filename: safeFilename, target: recipient,
    sent: 0, size: fileBuffer.length, status: 'sending',
  };

  webLog(`[Verzender] Start: '${safeFilename}' → '${recipient}'...`);

  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a) => webLog(a.join(' '));
  console.error = (...a) => webLog('[FOUT] ' + a.join(' '));

  performSendFlow(tmpFile, recipient, webState.username, webState.authToken, AUTH_HOST, AUTH_PORT_UI, (err) => {
    console.log = origLog;
    console.error = origErr;
    try { fs.unlinkSync(tmpFile); } catch { }
    const t = webState.activeTransfers.sends[tid];
    if (t) {
      t.status = err ? 'failed' : 'complete';
      if (!err) { t.sent = fileBuffer.length; }
      setTimeout(() => delete webState.activeTransfers.sends[tid], 10000);
    }
    if (err) webLog(`[Verzender] Mislukt: ${err}`);
    else webLog(`[Verzender] '${safeFilename}' succesvol verzonden naar '${recipient}'.`);
  });

  sendJSON(res, 200, { status: 'success', message: `Verzending gestart voor '${safeFilename}'.` });
}

async function handleWebAccept(req, res) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON.' }); }

  const t = webState.activeTransfers.receives[body.transferId];
  if (!t || t.status !== 'waiting_approval')
    return sendJSON(res, 404, { status: 'error', message: 'Transfer niet gevonden of niet in wachtstatus.' });

  webLog(`[Ontvanger] Geaccepteerd: '${t.filename}' van '${t.sender}'.`);
  t.status = 'receiving';

  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a) => webLog(a.join(' '));
  console.error = (...a) => webLog('[FOUT] ' + a.join(' '));
  t.acceptFn();
  console.log = origLog;
  console.error = origErr;

  setTimeout(() => {
    const tr = webState.activeTransfers.receives[body.transferId];
    if (tr) {
      tr.status = 'complete'; webState.hasNewFiles = true;
      setTimeout(() => delete webState.activeTransfers.receives[body.transferId], 10000);
    }
  }, 2000);

  sendJSON(res, 200, { status: 'success', message: 'Transfer geaccepteerd.' });
}

async function handleWebDecline(req, res) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON.' }); }

  const t = webState.activeTransfers.receives[body.transferId];
  if (!t || t.status !== 'waiting_approval')
    return sendJSON(res, 404, { status: 'error', message: 'Transfer niet gevonden of niet in wachtstatus.' });

  webLog(`[Ontvanger] Geweigerd: '${t.filename}' van '${t.sender}'.`);
  t.declineFn();
  delete webState.activeTransfers.receives[body.transferId];
  sendJSON(res, 200, { status: 'success', message: 'Transfer geweigerd.' });
}

async function handleWebLogout(req, res) {
  if (!webState.isOnline)
    return sendJSON(res, 400, { status: 'error', message: 'Node is al offline.' });

  webLog('[Logout] Node sessie beëindigd door gebruiker.');
  if (webState.samSocket) { try { webState.samSocket.destroy(); } catch { } webState.samSocket = null; }
  webState.isOnline = false; webState.username = null;
  webState.myBase32Address = null; webState.authToken = null;
  webState.activeTransfers = { sends: {}, receives: {} };
  sendJSON(res, 200, { status: 'success', message: 'Uitgelogd.' });
}

function handleWebStatus(req, res) {
  const url = new URL(req.url, `http://localhost:${UI_PORT}`);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const newLogs = webState.logs.slice(offset);

  const cleanReceives = {};
  for (const [id, t] of Object.entries(webState.activeTransfers.receives)) {
    cleanReceives[id] = { filename: t.filename, sender: t.sender, received: t.received, size: t.size, status: t.status };
  }

  const hadNewFiles = webState.hasNewFiles;
  webState.hasNewFiles = false;

  sendJSON(res, 200, {
    status: 'success',
    isOnline: webState.isOnline,
    username: webState.username,
    myBase32Address: webState.myBase32Address,
    logs: newLogs,
    activeTransfers: { sends: webState.activeTransfers.sends, receives: cleanReceives },
    hasNewFiles: hadNewFiles,
  });
}

function handleWebFiles(req, res) {
  try {
    fs.mkdirSync(RECEIVED_DIR, { recursive: true });
    const items = fs.readdirSync(RECEIVED_DIR)
      .filter(f => !f.endsWith('.tmp'))
      .map(f => {
        const s = fs.statSync(path.join(RECEIVED_DIR, f));
        return { name: f, size: s.size, mtime: s.mtimeMs };
      })
      .sort((a, b) => b.mtime - a.mtime);
    sendJSON(res, 200, { status: 'success', files: items });
  } catch (err) {
    sendJSON(res, 500, { status: 'error', message: err.message });
  }
}

function handleWebDownload(req, res) {
  const url = new URL(req.url, `http://localhost:${UI_PORT}`);
  const filename = url.searchParams.get('file');
  if (!filename) { res.writeHead(400); res.end('Missing file parameter.'); return; }
  const safe = path.basename(filename);
  if (!safe || safe.includes('..') || safe !== filename) { res.writeHead(400); res.end('Invalid filename.'); return; }
  const filePath = path.join(RECEIVED_DIR, safe);
  if (!fs.existsSync(filePath)) { res.writeHead(404); res.end('File not found.'); return; }
  const stat = fs.statSync(filePath);
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${safe}"`,
    'Content-Length': stat.size,
  });
  fs.createReadStream(filePath).pipe(res);
}

function handleWebShutdown(req, res) {
  webLog('[Shutdown] Terminatie ontvangen. Server stopt...');
  sendJSON(res, 200, { status: 'success', message: 'Server wordt afgesloten.' });
  if (webState.samSocket) { try { webState.samSocket.destroy(); } catch { } }
  setTimeout(() => process.exit(0), 500);
}

// ── PHP Auth Server starten ────────────────────────────────────────────
function startPhpServer(callback) {
  // Check of poort 8000 al in gebruik is (server draait al)
  const testSocket = net.connect({ host: '127.0.0.1', port: AUTH_PORT_UI }, () => {
    testSocket.destroy();
    webLog('[PHP Server] Auth server is al actief op poort ' + AUTH_PORT_UI + '.');
    callback();
  });

  testSocket.on('error', () => {
    // Poort vrij — start php server.php
    const phpScript = path.join(__dirname, 'server.php');
    if (!fs.existsSync(phpScript)) {
      webLog('[PHP Server] WAARSCHUWING: server.php niet gevonden! Auth server niet gestart.');
      return callback();
    }

    webLog('[PHP Server] Starten van server.php op poort ' + AUTH_PORT_UI + '...');

    const phpProc = spawn('php', [phpScript, String(AUTH_PORT_UI)], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });

    phpProc.stdout.on('data', data => {
      const lines = data.toString().trim().split('\n');
      lines.forEach(l => l && webLog('[PHP] ' + l.trim()));
    });
    phpProc.stderr.on('data', data => {
      const lines = data.toString().trim().split('\n');
      lines.forEach(l => l && webLog('[PHP FOUT] ' + l.trim()));
    });

    phpProc.on('exit', (code) => {
      webLog(`[PHP Server] server.php beëindigd (code ${code}).`);
    });

    // Wacht tot de PHP server luistert (max 5s)
    let tries = 0;
    const checkReady = () => {
      const s = net.connect({ host: '127.0.0.1', port: AUTH_PORT_UI }, () => {
        s.destroy();
        webLog('[PHP Server] Auth server luistert op poort ' + AUTH_PORT_UI + '. Klaar!');
        callback();
      });
      s.on('error', () => {
        tries++;
        if (tries >= 10) {
          webLog('[PHP Server] FOUT: Auth server reageerde niet na 5s.');
          callback();
        } else {
          setTimeout(checkReady, 500);
        }
      });
    };
    setTimeout(checkReady, 500);

    // Ruim PHP op bij afsluiten Node
    process.on('exit', () => { try { phpProc.kill(); } catch {} });
    process.on('SIGINT', () => { try { phpProc.kill(); } catch {} process.exit(0); });
    process.on('SIGTERM', () => { try { phpProc.kill(); } catch {} process.exit(0); });
  });
}

// ── HTTP Server + Router ──────────────────────────────────────────────────────
function startWebUI() {
  WEB_SESSION_TOKEN = crypto.randomBytes(32).toString('hex');

  // Log separator bij elke nieuwe start
  logStream.write('\n' + '='.repeat(60) + '\n');
  logStream.write(`[${new Date().toISOString()}] NEXUS SHARE gestart\n`);
  logStream.write('='.repeat(60) + '\n');

  // Eerst PHP auth server starten, dan pas de web UI
  startPhpServer(() => {
    const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', `http://localhost:${UI_PORT}`);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const urlPath = req.url.split('?')[0];

    // Statische bestanden
    if (req.method === 'GET' && urlPath === '/') return serveIndex(res);
    if (req.method === 'GET' && ['/app.js', '/index.css'].includes(urlPath))
      return serveStaticFile(res, path.join(PUBLIC_DIR, urlPath));

    // API — vereist geldig session token
    if (urlPath.startsWith('/api/')) {
      if (req.headers['x-session-token'] !== WEB_SESSION_TOKEN)
        return sendJSON(res, 403, { status: 'error', message: 'Ongeldig session token.' });

      try {
        if (req.method === 'POST' && urlPath === '/api/register') return await handleWebRegister(req, res);
        if (req.method === 'POST' && urlPath === '/api/login') return await handleWebLogin(req, res);
        if (req.method === 'POST' && urlPath === '/api/send') return await handleWebSend(req, res);
        if (req.method === 'POST' && urlPath === '/api/accept') return await handleWebAccept(req, res);
        if (req.method === 'POST' && urlPath === '/api/decline') return await handleWebDecline(req, res);
        if (req.method === 'POST' && urlPath === '/api/logout') return await handleWebLogout(req, res);
        if (req.method === 'POST' && urlPath === '/api/shutdown') return handleWebShutdown(req, res);
        if (req.method === 'GET' && urlPath === '/api/status') return handleWebStatus(req, res);
        if (req.method === 'GET' && urlPath === '/api/files') return handleWebFiles(req, res);
        if (req.method === 'GET' && urlPath === '/api/download') return handleWebDownload(req, res);
      } catch (err) {
        webLog(`[Server Fout] ${err.message}`);
        return sendJSON(res, 500, { status: 'error', message: 'Interne serverfout: ' + err.message });
      }

      return sendJSON(res, 404, { status: 'error', message: `Endpoint niet gevonden: ${urlPath}` });
    }

    res.writeHead(404); res.end('Not Found');
    });

    server.listen(UI_PORT, '127.0.0.1', () => {
      console.log('');
      console.log('╔══════════════════════════════════════════════════╗');
      console.log('║         NEXUS SHARE — Web UI (p2p.js)            ║');
      console.log('╠══════════════════════════════════════════════════╣');
      console.log(`║  URL:  http://localhost:${UI_PORT}                      ║`);
      console.log(`║  Log:  nexus.log                                  ║`);
      console.log('╚══════════════════════════════════════════════════╝');
      console.log('');
      console.log('Browser opent automatisch. Druk CTRL+C om te stoppen.');
      webLog('[Server] Web UI actief op poort ' + UI_PORT + '.');
      exec(`start http://localhost:${UI_PORT}`);
    });

    server.on('error', err => {
      if (err.code === 'EADDRINUSE')
        console.error(`\n[FOUT] Poort ${UI_PORT} is al in gebruik. Stop het andere programma.\n`);
      else
        console.error('[Server Fout]', err.message);
      process.exit(1);
    });
  }); // einde startPhpServer callback
}

