const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');

const USERS_JSON_PATH = path.join(__dirname, 'users.json');
const TEST_FILE_PATH = path.join(__dirname, 'test.txt');
const RECEIVED_FILE_PATH = path.join(__dirname, 'received', 'test.txt');

// Import login and performSendFlow from p2p.js
const { login, lookup, convertI2PBase64toBase32, performSendFlow } = require('./p2p.js');

const AUTH_HOST = '127.0.0.1';
const AUTH_PORT = 8000;

console.log('=== START E2E INTEGRATIETEST (I2P/SOCKS5) ===\n');

// Configureer omgevingsvariabelen voor automatische acceptatie en time-out
process.env.AUTO_ACCEPT = 'true';
process.env.SOCKET_TIMEOUT = '30000';

let phpServerProcess = null;
let bobNodeProcess = null;

async function cleanupAndExit(exitCode) {
  console.log('\nProcessen aan het opruimen...');
  
  if (bobNodeProcess) {
    console.log('- Bob P2P Node stoppen...');
    try { bobNodeProcess.kill('SIGINT'); } catch (e) {}
  }
  if (phpServerProcess) {
    console.log('- PHP Directory Server stoppen...');
    try { phpServerProcess.kill(); } catch (e) {}
  }
  
  // Windows-specific cleanup
  console.log('- Windows processen opschonen...');
  try {
    const { execSync } = require('child_process');
    execSync('taskkill /F /IM i2pd.exe', { stdio: 'ignore' });
    execSync('taskkill /F /FI "WINDOWTITLE eq Bob Test Node*"', { stdio: 'ignore' });
    execSync('taskkill /F /FI "WINDOWTITLE eq Centrale PHP Server*"', { stdio: 'ignore' });
  } catch (e) {}
  
  console.log(`Testsuite voltooid met exit code ${exitCode}.`);
  process.exit(exitCode);
}

// Zorg voor nette afsluiting bij interrupts
process.on('SIGINT', () => cleanupAndExit(1));
process.on('SIGTERM', () => cleanupAndExit(1));

async function runTest() {
  try {
    // 1. Schone start: wis users.json
    if (fs.existsSync(USERS_JSON_PATH)) {
      console.log('Oude users.json gedetecteerd. Verwijderen...');
      fs.unlinkSync(USERS_JSON_PATH);
    }
    
    // Wis eventueel oud ontvangen bestand
    if (fs.existsSync(RECEIVED_FILE_PATH)) {
      fs.unlinkSync(RECEIVED_FILE_PATH);
    }

    // Maak een uniek testbestand aan
    const testInhoud = 'Dit is een uniek beveiligd testbestand dat succesvol over I2P SOCKS5 is verzonden! ' + Date.now();
    fs.writeFileSync(TEST_FILE_PATH, testInhoud);
    console.log('Testbestand aangemaakt:', TEST_FILE_PATH);

    // 2. Start de PHP Directory Server
    console.log('PHP Directory Server starten...');
    phpServerProcess = spawn('php', ['-d', 'extension=openssl', '-d', 'extension=sockets', 'server.php', '8000'], {
      cwd: __dirname,
      stdio: 'pipe'
    });

    phpServerProcess.stdout.on('data', data => {
      console.log(`[PHP Server]: ${data.toString().trim()}`);
    });
    phpServerProcess.stderr.on('data', data => {
      console.error(`[PHP Server ERROR]: ${data.toString().trim()}`);
    });

    // Wacht 2 seconden tot de PHP server online is
    await new Promise(r => setTimeout(r, 2000));

    // 3. Registreer Alice en Bob
    console.log('Registreren van testgebruikers via p2p.js register...');
    await new Promise((resolve, reject) => {
      const regAlice = spawn('node', ['p2p.js', 'register', 'alice', 'alicepassword', AUTH_HOST, AUTH_PORT], { cwd: __dirname });
      regAlice.on('close', code => code === 0 ? resolve() : reject(new Error('Registratie Alice mislukt')));
    });
    console.log('Alice geregistreerd.');

    await new Promise((resolve, reject) => {
      const regBob = spawn('node', ['p2p.js', 'register', 'bob', 'bobpassword', AUTH_HOST, AUTH_PORT], { cwd: __dirname });
      regBob.on('close', code => code === 0 ? resolve() : reject(new Error('Registratie Bob mislukt')));
    });
    console.log('Bob geregistreerd.');

    // 4. Start Bob Receiver Node
    console.log("Bob P2P Node opstarten in receive modus...");
    bobNodeProcess = spawn('node', ['p2p.js', 'receive', 'bob', 'bobpassword', '9090', AUTH_HOST, AUTH_PORT], {
      cwd: __dirname,
      stdio: 'pipe'
    });
    // Give I2P SAM bridge extra time to be fully ready before first send attempt
    await new Promise(r => setTimeout(r, 12000)); // 12 seconds warm‑up

    // Give I2P SAM bridge some time to become fully ready before first send attempt
    await new Promise(r => setTimeout(r, 8000)); // 8 seconds warm‑up

    bobNodeProcess.stdout.on('data', data => {
      console.log(`[Bob Node]: ${data.toString().trim()}`);
    });
    bobNodeProcess.stderr.on('data', data => {
      console.error(`[Bob Node ERROR]: ${data.toString().trim()}`);
    });

    // 5. Inloggen als Alice
    console.log('Inloggen bij directory server als Alice...');
    const sessionToken = await new Promise((resolve, reject) => {
      login('alice', 'alicepassword', 'I2P_SOCKS5_CLIENT', AUTH_HOST, AUTH_PORT, (err, token) => {
        if (err) reject(err);
        else resolve(token);
      });
    });
    console.log('Alice succesvol ingelogd.');

    // 6. Wachten tot Bob online is en zijn Base32 I2P-adres heeft geregistreerd
    console.log("Wachten tot Bob online komt en zijn Base32 I2P-adres registreert (retry loop)...");
    let bobAddress = null;
    let retries = 0;
    const maxLookupRetries = 60;
    while (retries < maxLookupRetries) {
      try {
        bobAddress = await new Promise((resolve, reject) => {
          lookup(sessionToken, 'bob', AUTH_HOST, AUTH_PORT, (err, addr) => {
            if (err) reject(err);
            else resolve(addr);
          });
        });
        if (bobAddress) break;
      } catch (err) {
        // Bob is nog niet online
      }
      retries++;
      process.stdout.write('.');
      await new Promise(r => setTimeout(r, 2000));
    }
    
    if (!bobAddress) {
      throw new Error('Bob is niet online gekomen binnen de verwachte tijd (90 seconden).');
    }
    
    console.log('\nBob adres gevonden:', bobAddress);
    if (!bobAddress.endsWith('.i2p')) {
      bobAddress = convertI2PBase64toBase32(bobAddress);
      console.log('Bob geconverteerd Base32 adres:', bobAddress);
    }

    // 7. Voer de beveiligde bestandsoverdracht uit over I2P SOCKS5
    console.log('[Test] Start bestandsoverdracht via performSendFlow over I2P SOCKS5 proxy...');
    let transferSuccess = false;
    let attempts = 0;
    const maxAttempts = 15;
    
    while (attempts < maxAttempts) {
      attempts++;
      console.log(`Poging ${attempts} van ${maxAttempts}...`);
      
      const sendPromise = new Promise((resolve) => {
        performSendFlow(TEST_FILE_PATH, 'bob', 'alice', sessionToken, AUTH_HOST, AUTH_PORT, () => {
          resolve();
        });
      });
      
      await sendPromise;
      
      // Controleer of het bestand correct is ontvangen en geschreven
      if (fs.existsSync(RECEIVED_FILE_PATH)) {
        const receivedInhoud = fs.readFileSync(RECEIVED_FILE_PATH, 'utf8');
        if (receivedInhoud === testInhoud) {
          transferSuccess = true;
          break;
        }
      }
      
      console.log(`  -> Poging ${attempts} voltooid, maar bestand is nog niet correct ontvangen. Wachten op tunnel warm-up (3s)...`);
      await new Promise(r => setTimeout(r, 3000));
    }

    if (!transferSuccess) {
      throw new Error(`Bestandsoverdracht faalde na ${maxAttempts} pogingen.`);
    }

    console.log('  -> [GESLAAGD] Bestand succesvol overgedragen en geverifieerd!');
    console.log('\n=== INTEGRATIETEST SUCCESVOL VOLTOOID EN GESLAAGD ===');
    cleanupAndExit(0);
  } catch (err) {
    console.error('\n[TEST MISLUKT] De integratietest faalde:', err.message);
    cleanupAndExit(1);
  }
}

runTest();
