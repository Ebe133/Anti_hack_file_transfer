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
const readline = require('readline');
const { execSync, spawn } = require('child_process');
const https = require('https');

// I2P Configuratie
const I2P_CONFIG = {
  samHost: '127.0.0.1',
  samPort: 7656,            // SAM Bridge voor inkomende stream tunnels
  socksHost: '127.0.0.1',
  socksPort: 4447           // SOCKS5 proxy voor uitgaande verbindingen
};

if (require.main === module) {
  const [modus, ...restArgs] = process.argv.slice(2);

  if (!modus || !['register', 'receive', 'send', 'multi'].includes(modus)) {
    toonGebruik();
    process.exit(1);
  }

  switch (modus) {
    case 'register':
      handleRegister(restArgs);
      break;
    case 'receive':
      handleReceive(restArgs);
      break;
    case 'send':
      handleSend(restArgs);
      break;
    case 'multi':
      handleMulti(restArgs);
      break;
  }
}

function toonGebruik() {
  console.log('Gebruik:');
  console.log('  node p2p.js register <username> <password> <auth_host> <auth_port>');
  console.log('  node p2p.js receive  <my_username> <my_password> <my_port> <auth_host> <auth_port>');
  console.log('  node p2p.js send     <file> <target_username> <my_username> <my_password> <auth_host> <auth_port>');
  console.log('  node p2p.js multi    <my_username> <my_password> <my_port> <auth_host> <auth_port>');
}

/**
 * Registreert een account bij de PHP auth server.
 */
function handleRegister(args) {
  const [username, password, authHost, authPort] = args;
  if (!username || !password || !authHost || !authPort) {
    console.error('Fout: Ontbrekende argumenten voor register.');
    toonGebruik();
    process.exit(1);
  }

  const client = net.connect({ host: authHost, port: parseInt(authPort, 10) }, () => {
    client.write(JSON.stringify({
      action: 'register',
      username: username,
      password: password
    }) + '\n');
  });

  client.on('data', data => {
    try {
      const res = JSON.parse(data.toString().trim());
      if (res.status === 'success') {
        console.log('Succes:', res.message);
      } else {
        console.error('Fout:', res.message);
      }
    } catch (e) {
      console.error('Fout bij parsen antwoord:', data.toString());
    }
    client.destroy();
  });

  client.on('error', err => {
    console.error('Netwerkfout bij verbinding met auth server:', err.message);
  });
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
function startReceiver(myUsername, sessionToken, myPort, authHost, authPort, base32Address, samSessionID, isMulti = false) {
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

        // Beveiliging: Vraag handmatig toestemming via de console alvorens bytes te ontvangen
        const isAutoAccept = process.env.AUTO_ACCEPT === 'true';
        if (isAutoAccept) {
          console.log('[P2P Ontvanger] AUTO_ACCEPT actief. Overdracht automatisch geaccepteerd.');
          
          // Open bestand voor schrijven
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
          socket.write('ACCEPT\n');
          processPayload();
        } else {
          socket.pause(); // Pauzeer netwerkstroom tijdens het prompten
          
          console.log(`\n=== INKOMENDE OVERDRACHT VERZOEK ===`);
          console.log(`  Afzender:     ${fileInfo.username}`);
          console.log(`  Bestand:      ${veiligeNaam}`);
          console.log(`  Grootte:      ${(fileInfo.file_size / (1024 * 1024)).toFixed(2)} MB (${fileInfo.file_size} bytes)`);
          
          const acceptRl = readline.createInterface({ input: process.stdin, output: process.stdout });
          acceptRl.question('Wilt u dit bestand ontvangen? (j/n): ', (antwoord) => {
            acceptRl.close();
            const a = antwoord.trim().toLowerCase();
            
            if (a === 'j' || a === 'ja' || a === 'y' || a === 'yes') {
              console.log('[P2P Ontvanger] Overdracht geaccepteerd. Start download...');
              
              // Open bestand voor schrijven
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
              socket.resume(); // Hervat netwerkstroom
              socket.write('ACCEPT\n');
              processPayload();
            } else {
              console.log('[P2P Ontvanger] Overdracht geweigerd.');
              socket.write('DECLINE: Geweigerd door ontvanger\n');
              socket.destroy();
              cleanup();
              if (isMulti) {
                process.stdout.write('\n> ');
              }
            }
          });
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
        try { fs.unlinkSync(tempPath); } catch (e) {}
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

function handleReceive(args) {
  const [myUsername, myPassword, myPort, authHost, authPort] = args;
  if (!myUsername || !myPassword || !myPort || !authHost || !authPort) {
    console.error('Fout: Ontbrekende parameters.');
    toonGebruik();
    process.exit(1);
  }

  initI2PAndLogin(myPort, myUsername, myPassword, authHost, authPort, (err, info) => {
    if (err) {
      console.error('[FOUT]', err.message);
      process.exit(1);
    }
    console.log('Login succesvol!');
    startReceiver(myUsername, info.sessionToken, myPort, authHost, authPort, info.myBase32Address, info.sessionID, false);
  });
}

function handleSend(args) {
  const [file, targetUsername, myUsername, myPassword, authHost, authPort] = args;
  if (!file || !targetUsername || !myUsername || !myPassword || !authHost || !authPort) {
    console.error('Fout: Ontbrekende parameters.');
    toonGebruik();
    process.exit(1);
  }

  checkAndInstallI2P((i2pErr) => {
    if (i2pErr) {
      console.error(`\n[I2P FOUT] Automatische I2P-opstart of download mislukt (${i2pErr.message}).`);
      process.exit(1);
    }

    console.log('Inloggen bij directory server...');
    login(myUsername, myPassword, 'I2P_SOCKS5_CLIENT', authHost, authPort, (loginErr, sessionToken) => {
      if (loginErr) {
        console.error('Login mislukt:', loginErr.message);
        process.exit(1);
      }
      console.log('Login succesvol!');
      performSendFlow(file, targetUsername, myUsername, sessionToken, authHost, authPort, () => {
        console.log('Klaar met verzenden.');
        process.exit(0);
      });
    });
  });
}

/**
 * Start node in multi-mode (interactieve shell en luisteren).
 */
function handleMulti(args) {
  const [myUsername, myPassword, myPort, authHost, authPort] = args;
  if (!myUsername || !myPassword || !myPort || !authHost || !authPort) {
    console.error('Fout: Ontbrekende parameters.');
    toonGebruik();
    process.exit(1);
  }

  let startInteractiveConsole = (sessionToken, base32Address, sessionID) => {
    startReceiver(myUsername, sessionToken, myPort, authHost, authPort, base32Address, sessionID, true);

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    console.log('\n=== Interactieve P2P Console ===');
    console.log('Typ: send <bestandspad> <gebruikersnaam> (om bestand te sturen)');
    console.log('Typ: exit (om af te sluiten)\n');

    const promptUser = () => {
      rl.question('> ', input => {
        const parts = input.trim().split(/\s+/);
        const command = parts[0];

        if (command === 'send') {
          const file = parts[1];
          const target = parts[2];
          if (!file || !target) {
            console.log('Gebruik: send <bestandspad> <gebruikersnaam>');
            promptUser();
            return;
          }
          performSendFlow(file, target, myUsername, sessionToken, authHost, authPort, () => {
            promptUser();
          });
        } else if (command === 'exit') {
          console.log('Sluiten...');
          rl.close();
          process.exit(0);
        } else if (command === '') {
          promptUser();
        } else {
          console.log('Onbekend commando. Gebruik: send <bestandspad> <gebruikersnaam> OF exit');
          promptUser();
        }
      });
    };
    promptUser();
  };

  initI2PAndLogin(myPort, myUsername, myPassword, authHost, authPort, (err, info) => {
    if (err) {
      console.error('[FOUT]', err.message);
      process.exit(1);
    }
    console.log('Login succesvol!');
    startInteractiveConsole(info.sessionToken, info.myBase32Address, info.sessionID);
  });
}

let i2pChildProcess = null;

// Ruim het I2P-achtergrondproces op bij het afsluiten van Node
function cleanupI2p() {
  if (i2pChildProcess) {
    console.log('[I2P Manager] Stoppen van lokale i2pd daemon...');
    try {
      i2pChildProcess.kill();
    } catch (e) {}
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
    const maxRetries = 20;
    
    function checkSamOnline() {
      const socket = net.connect({ port: 7656, host: '127.0.0.1' }, () => {
        socket.destroy();
        console.log('[I2P Manager] SAM Bridge is online gekomen en luistert!');
        callback(null, i2pChildProcess);
      });
      
      socket.on('error', () => {
        retries++;
        if (retries >= maxRetries) {
          callback(new Error('SAM Bridge startte niet op binnen de verwachte tijd (20s).'));
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
  I2P_CONFIG
};


