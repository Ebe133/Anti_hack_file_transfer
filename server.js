const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const bytes = require('bytes');

// Lees het poortnummer uit de command line argumenten (bijv. node server.js 8080)
const port = Number(process.argv[2]);
if (!port) {
  console.log('Gebruik: node server.js <poort>');
  process.exit(1);
}

// Bepaal de map waar alle ontvangen bestanden in worden opgeslagen
const receiveDir = path.join(__dirname, 'received');
fs.mkdirSync(receiveDir, { recursive: true });

// Limieten voor uploads
const AUTO_FILE_SIZE = bytes('10MB'); // Bestanden tot 10MB worden direct zonder prompt geaccepteerd
const MAX_TIME_DIFF = 60000; // Maximale afwijking in tijdstempel (60 seconden) om replay-aanvallen te voorkomen

// Start de TCP server. We gebruiken `allowHalfOpen: true` zodat de verbinding
// open blijft nadat de client klaar is met sturen (client stuurt FIN),
// zodat de server de succesmelding nog terug kan sturen.
const server = net.createServer({ allowHalfOpen: true }, handleConnection);
server.listen(port, () => console.log('Server gestart op poort ' + port));

// Behandel de verbinding met een client
function handleConnection(socket) {
  // Voorkom dat socket-fouten (zoals een plotselinge disconnect) de server laten crashen
  socket.on('error', err => {
    console.error('Socket fout:', err.message);
    socket.destroy();
  });

  // Lees eerst de eerste regel met de JSON metadata
  readFirstLine(socket, (line, rest) => {
    let metadata;
    try {
      metadata = JSON.parse(line);
    } catch (err) {
      // Sluit verbinding direct als de metadata geen geldige JSON is
      socket.end('FOUT ongeldige metadata\n');
      return;
    }

    // Controleer of de client een upload of download wil starten
    if (metadata.mode === 'upload') {
      const reason = validateMetadata(metadata);
      if (reason) {
        socket.end('FOUT geweigerd: ' + reason + '\n');
        return;
      }

      // Vraag handmatige toestemming als het bestand groter is dan 10MB
      if (metadata.size > AUTO_FILE_SIZE) {
        askPermission(metadata, (approved) => {
          if (!approved) {
            socket.end('FOUT geweigerd: ontvanger heeft de upload afgewezen\n');
            return;
          }
          // Start de upload zonder limiet (Infinity)
          receiveUpload(socket, metadata, rest, Infinity);
        });
      } else {
        // Start de upload met de automatische limiet van 10MB
        receiveUpload(socket, metadata, rest, AUTO_FILE_SIZE);
      }
    } else if (metadata.mode === 'download') {
      // Start de download flow
      sendDownload(socket, metadata.filename);
    } else {
      socket.end('FOUT onbekend commando: ' + metadata.mode + '\n');
    }
  });
}

// Controleer of de metadata klopt
function validateMetadata(metadata) {
  if (!safeFilename(metadata.filename)) return 'ongeldige bestandsnaam';
  if (!(metadata.size > 0)) return 'bestandsgrootte ongeldig';
  // Controleer of de tijdstempel te ver afwijkt van de huidige servertijd
  if (Math.abs(Date.now() - metadata.time) > MAX_TIME_DIFF) return 'tijdstempel buiten bereik';
  return null;
}

// Vraag toestemming in de serverconsole voor grote bestanden
function askPermission(metadata, done) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const question = `Upload "${metadata.filename}" is ${bytes(metadata.size)} (groter dan ${bytes(AUTO_FILE_SIZE)}). Accepteren? (j/n): `;

  const ask = () => rl.question(question, (answer) => {
    const text = answer.trim().toLowerCase();
    if (text === 'j' || text === 'ja' || text === 'y' || text === 'yes') {
      rl.close();
      done(true);
    } else if (text === 'n' || text === 'nee' || text === 'no') {
      rl.close();
      done(false);
    } else {
      console.log('Antwoord met j (ja) of n (nee).');
      ask();
    }
  });
  ask();
}

// Zorg ervoor dat de bestandsnaam veilig is en niet uit de receiveDir kan ontsnappen
function safeFilename(name) {
  if (!name) return false;
  if (name.includes('/') || name.includes('\\')) return false; // Geen mappenpaden
  if (name.includes('..')) return false; // Geen parent directory tricks
  return true;
}

// Ontvang en schrijf het bestand naar de disk
function receiveUpload(socket, metadata, firstChunk, limit) {
  // Zorg ervoor dat de ontvangstmap bestaat (voor het geval deze is verwijderd)
  fs.mkdirSync(receiveDir, { recursive: true });

  const filePath = path.join(receiveDir, metadata.filename);
  const target = fs.createWriteStream(filePath);
  let received = 0;
  let aborted = false;

  // Bereken tijdens het ontvangen een SHA-256 hash van de bytes die binnenkomen.
  // Hiermee kunnen we (a) controleren of het bestand onderweg niet is gewijzigd
  // en (b) de hash opslaan zodat we dit later bij de download kunnen verifiëren.
  const hash = crypto.createHash('sha256');

  // Centrale helper om de streams te sluiten en het bestand te verwijderen bij een fout of limietoverschrijding
  function closeAndCleanup() {
    aborted = true;
    target.destroy();
    try {
      fs.rmSync(filePath, { force: true });
    } catch (e) {}
  }

  // Behandel schrijf-fouten naar de disk (bijv. geen schijfruimte)
  target.on('error', (err) => {
    if (aborted) return;
    console.error('Fout bij opslaan bestand:', err.message);
    socket.end('FOUT server schrijf error: ' + err.message + '\n');
    closeAndCleanup();
  });

  // Functie om stukken binnengekomen data te verwerken en te schrijven
  function handleChunk(chunk) {
    if (aborted) return;
    received += chunk.length;

    // Beveiliging: sluit verbinding direct af als de client meer stuurt dan de afgesproken limiet
    if (received > limit) {
      socket.destroy();
      closeAndCleanup();
      console.log('Upload afgebroken: groter dan limiet');
      return;
    }
    hash.update(chunk); // Voed elk binnengekomen blok aan de hashberekening
    target.write(chunk);
  }

  // Schrijf de eerste byte(s) die al samen met de metadata waren binnengekomen
  handleChunk(firstChunk);

  // Luister naar binnenkomende datablokken
  socket.on('data', handleChunk);

  // Wanneer de client klaar is met sturen (socket.end())
  socket.on('end', () => {
    if (aborted) return;
    // Zorg ervoor dat alle data naar de disk is geschreven voordat we succes sturen
    target.end(() => {
      if (aborted) return;

      // Rond de hashberekening af en vergelijk met de hash die de client meestuurde.
      // Verschillen zij, dan is het bestand onderweg gewijzigd of beschadigd.
      const computedHash = hash.digest('hex');
      if (metadata.hash && metadata.hash !== computedHash) {
        closeAndCleanup();
        socket.end('FOUT integriteitscontrole mislukt: bestand is tijdens upload gewijzigd\n');
        console.log('Upload geweigerd: hash komt niet overeen voor ' + metadata.filename);
        return;
      }

      // Sla de hash op naast het bestand (sidecar bestand) zodat we deze
      // bij een latere download kunnen controleren.
      try {
        fs.writeFileSync(filePath + '.sha256', computedHash);
      } catch (e) {
        console.error('Kon hash niet opslaan:', e.message);
      }

      socket.end('OK geupload: ' + metadata.filename + ' (sha256: ' + computedHash + ')\n');
      console.log('succesfull upload: ' + metadata.filename + ' sha256=' + computedHash);
    });
  });
}

// Verstuur een opgevraagd bestand naar de client
function sendDownload(socket, filename) {
  // Controleer of de bestandsnaam veilig is
  if (!safeFilename(filename)) {
    socket.end('FOUT ongeldige bestandsnaam\n');
    return;
  }

  const storagePath = path.join(receiveDir, filename);

  // Vraag bestandsgrootte op om te controleren of het bestaat en hoe groot het is
  fs.stat(storagePath, (err, stats) => {
    if (err) {
      socket.end('FOUT bestand niet gevonden\n');
      return;
    }

    // Lees de bij de upload opgeslagen hash op (indien aanwezig).
    let storedHash = null;
    try {
      storedHash = fs.readFileSync(storagePath + '.sha256', 'utf8').trim();
    } catch (e) {
      storedHash = null; // Geen sidecar: oud bestand zonder hash
    }

    // Integriteitscontrole: bereken de actuele hash van het bestand op schijf en
    // vergelijk met de opgeslagen hash. Komen ze niet overeen, dan is het bestand
    // na de upload gewijzigd (bijv. handmatig aangepast) en weigeren we de download.
    if (storedHash) {
      const currentHash = crypto.createHash('sha256')
        .update(fs.readFileSync(storagePath))
        .digest('hex');
      if (currentHash !== storedHash) {
        socket.end('FOUT integriteitscontrole mislukt: bestand is gewijzigd na upload\n');
        console.log('Download geweigerd: hash komt niet overeen voor ' + filename);
        return;
      }
    }

    // Stuur eerst een header regel met de bestandsgrootte en de hash
    // (bijv. "SIZE 12345 <sha256>\n"). De client kan de hash gebruiken om
    // ook de download zelf op transportfouten te controleren.
    socket.write(`SIZE ${stats.size} ${storedHash || ''}\n`);

    // Stream de bestandsinhoud direct door naar de client via een read stream
    const readStream = fs.createReadStream(storagePath);

    // Voorkom server crashes bij fouten tijdens het lezen van het bestand
    readStream.on('error', (readErr) => {
      console.error('Fout bij lezen bestand voor download:', readErr.message);
      socket.end('FOUT leesfout op server\n');
    });

    readStream.pipe(socket);
  });
}

// Hulpmiddel om de eerste regel (metadata) uit de TCP stream te vissen.
// Omdat TCP stromend is, kan één 'data' event een deel van de regel bevatten,
// of de regel plus een deel van de bestandsinhoud. We bufferen tot de eerste newline (\n).
function readFirstLine(socket, done) {
  let buffer = Buffer.alloc(0);
  socket.on('data', function onData(chunk) {
    buffer = Buffer.concat([buffer, chunk]);
    const lineEnd = buffer.indexOf(10); // Byte index 10 is de newline (\n)
    if (lineEnd === -1) return; // Wacht op meer data als er nog geen newline is

    // Verwijder deze listener zodat de rest van de data rechtstreeks naar de bestandsschrijver gaat
    socket.removeListener('data', onData);

    // Geef de regel (metadata) en het restant (bestandsdata) door aan de callback
    done(buffer.slice(0, lineEnd).toString(), buffer.slice(lineEnd + 1));
  });
}
 