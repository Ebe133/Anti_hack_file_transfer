const net = require('net');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const bytes = require('bytes');

// Lees het poortnummer uit de command line argumenten (bijv. node server.js 8080)
const poort = Number(process.argv[2]);
if (!poort) {
  console.log('Gebruik: node server.js <poort>');
  process.exit(1);
}

// Bepaal de map waar alle ontvangen bestanden in worden opgeslagen
const ontvangMap = path.join(__dirname, 'received');
fs.mkdirSync(ontvangMap, { recursive: true });

// Limieten voor uploads
const AUTO_BESTANDSGROOTTE = bytes('10MB'); // Bestanden tot 10MB worden direct zonder prompt geaccepteerd
const MAX_TIJDSVERSCHIL = 60000; // Maximale afwijking in tijdstempel (60 seconden) om replay-aanvallen te voorkomen

// Start de TCP server. We gebruiken `allowHalfOpen: true` zodat de verbinding
// open blijft nadat de client klaar is met sturen (client stuurt FIN),
// zodat de server de succesmelding nog terug kan sturen.
const server = net.createServer({ allowHalfOpen: true }, behandelVerbinding);
server.listen(poort, () => console.log('Server gestart op poort ' + poort));

// Behandel de verbinding met een client
function behandelVerbinding(socket) {
  // Voorkom dat socket-fouten (zoals een plotselinge disconnect) de server laten crashen
  socket.on('error', err => {
    console.error('Socket fout:', err.message);
    socket.destroy();
  });

  // Lees eerst de eerste regel met de JSON metadata
  leesEersteRegel(socket, (regel, rest) => {
    let metadata;
    try {
      metadata = JSON.parse(regel);
    } catch (fout) {
      // Sluit verbinding direct als de metadata geen geldige JSON is
      socket.end('FOUT ongeldige metadata\n');
      return;
    }

    // Controleer of de client een upload of download wil starten
    if (metadata.mode === 'upload') {
      const reden = valideerMetadata(metadata);
      if (reden) {
        socket.end('FOUT geweigerd: ' + reden + '\n');
        return;
      }

      // Vraag handmatige toestemming als het bestand groter is dan 10MB
      if (metadata.size > AUTO_BESTANDSGROOTTE) {
        vraagToestemming(metadata, (akkoord) => {
          if (!akkoord) {
            socket.end('FOUT geweigerd: ontvanger heeft de upload afgewezen\n');
            return;
          }
          // Start de upload zonder limiet (Infinity)
          ontvangUpload(socket, metadata, rest, Infinity);
        });
      } else {
        // Start de upload met de automatische limiet van 10MB
        ontvangUpload(socket, metadata, rest, AUTO_BESTANDSGROOTTE);
      }
    } else if (metadata.mode === 'download') {
      // Start de download flow
      verstuurDownload(socket, metadata.filename);
    } else {
      socket.end('FOUT onbekend commando: ' + metadata.mode + '\n');
    }
  });
}

// Controleer of de metadata klopt
function valideerMetadata(metadata) {
  if (!veiligeBestandsnaam(metadata.filename)) return 'ongeldige bestandsnaam';
  if (!(metadata.size > 0)) return 'bestandsgrootte ongeldig';
  // Controleer of de tijdstempel te ver afwijkt van de huidige servertijd
  if (Math.abs(Date.now() - metadata.time) > MAX_TIJDSVERSCHIL) return 'tijdstempel buiten bereik';
  return null;
}

// Vraag toestemming in de serverconsole voor grote bestanden
function vraagToestemming(metadata, klaar) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const vraag = `Upload "${metadata.filename}" is ${bytes(metadata.size)} (groter dan ${bytes(AUTO_BESTANDSGROOTTE)}). Accepteren? (j/n): `;
  
  const stel = () => rl.question(vraag, (antwoord) => {
    const tekst = antwoord.trim().toLowerCase();
    if (tekst === 'j' || tekst === 'ja' || tekst === 'y' || tekst === 'yes') {
      rl.close();
      klaar(true);
    } else if (tekst === 'n' || tekst === 'nee' || tekst === 'no') {
      rl.close();
      klaar(false);
    } else {
      console.log('Antwoord met j (ja) of n (nee).');
      stel();
    }
  });
  stel();
}

// Zorg ervoor dat de bestandsnaam veilig is en niet uit de ontvangMap kan ontsnappen
function veiligeBestandsnaam(naam) {
  if (!naam) return false;
  if (naam.includes('/') || naam.includes('\\')) return false; // Geen mappenpaden
  if (naam.includes('..')) return false; // Geen parent directory tricks
  return true;
}

// Ontvang en schrijf het bestand naar de disk
function ontvangUpload(socket, metadata, eersteStuk, limiet) {
  // Zorg ervoor dat de ontvangstmap bestaat (voor het geval deze is verwijderd)
  fs.mkdirSync(ontvangMap, { recursive: true });

  const pad = path.join(ontvangMap, metadata.filename);
  const doel = fs.createWriteStream(pad);
  let ontvangen = 0;
  let afgebroken = false;

  // Centrale helper om de streams te sluiten en het bestand te verwijderen bij een fout of limietoverschrijding
  function sluitEnRuimOp() {
    afgebroken = true;
    doel.destroy();
    try {
      fs.rmSync(pad, { force: true });
    } catch (e) {}
  }

  // Behandel schrijf-fouten naar de disk (bijv. geen schijfruimte)
  doel.on('error', (err) => {
    if (afgebroken) return;
    console.error('Fout bij opslaan bestand:', err.message);
    socket.end('FOUT server schrijf error: ' + err.message + '\n');
    sluitEnRuimOp();
  });

  // Functie om stukken binnengekomen data te verwerken en te schrijven
  function verwerk(stuk) {
    if (afgebroken) return;
    ontvangen += stuk.length;

    // Beveiliging: sluit verbinding direct af als de client meer stuurt dan de afgesproken limiet
    if (ontvangen > limiet) {
      socket.destroy();
      sluitEnRuimOp();
      console.log('Upload afgebroken: groter dan limiet');
      return;
    }
    doel.write(stuk);
  }

  // Schrijf de eerste byte(s) die al samen met de metadata waren binnengekomen
  verwerk(eersteStuk);

  // Luister naar binnenkomende datablokken
  socket.on('data', verwerk);

  // Wanneer de client klaar is met sturen (socket.end())
  socket.on('end', () => {
    if (afgebroken) return;
    // Zorg ervoor dat alle data naar de disk is geschreven voordat we succes sturen
    doel.end(() => {
      if (afgebroken) return;
      socket.end('OK geupload: ' + metadata.filename + '\n');
      console.log('succesfull upload: ' + metadata.filename);
    });
  });
}

// Verstuur een opgevraagd bestand naar de client
function verstuurDownload(socket, bestand) {
  // Controleer of de bestandsnaam veilig is
  if (!veiligeBestandsnaam(bestand)) {
    socket.end('FOUT ongeldige bestandsnaam\n');
    return;
  }

  const opslagPad = path.join(ontvangMap, bestand);

  // Vraag bestandsgrootte op om te controleren of het bestaat en hoe groot het is
  fs.stat(opslagPad, (err, stats) => {
    if (err) {
      socket.end('FOUT bestand niet gevonden\n');
      return;
    }

    // Stuur eerst de bestandsgrootte als header regel (bijv. "SIZE 12345\n")
    socket.write(`SIZE ${stats.size}\n`);

    // Stream de bestandsinhoud direct door naar de client via een read stream
    const leesStream = fs.createReadStream(opslagPad);
    
    // Voorkom server crashes bij fouten tijdens het lezen van het bestand
    leesStream.on('error', (leeslint) => {
      console.error('Fout bij lezen bestand voor download:', leeslint.message);
      socket.end('FOUT leesfout op server\n');
    });

    leesStream.pipe(socket);
  });
}

// Hulpmiddel om de eerste regel (metadata) uit de TCP stream te vissen.
// Omdat TCP stromend is, kan één 'data' event een deel van de regel bevatten,
// of de regel plus een deel van de bestandsinhoud. We bufferen tot de eerste newline (\n).
function leesEersteRegel(socket, klaar) {
  let buffer = Buffer.alloc(0);
  socket.on('data', function opData(stuk) {
    buffer = Buffer.concat([buffer, stuk]);
    const einde = buffer.indexOf(10); // Byte index 10 is de newline (\n)
    if (einde === -1) return; // Wacht op meer data als er nog geen newline is
    
    // Verwijder deze listener zodat de rest van de data rechtstreeks naar de bestandsschrijver gaat
    socket.removeListener('data', opData);
    
    // Geef de regel (metadata) en het restant (bestandsdata) door aan de callback
    klaar(buffer.slice(0, einde).toString(), buffer.slice(einde + 1));
  });
}
