 const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Lees de parameters: upload/download, bestandspad, host en poort (bijv. node client.js upload test.txt localhost 8080)
const [mode, file, host, port] = process.argv.slice(2);
if (!mode || !file || !host || !port || (mode !== 'upload' && mode !== 'download')) {
  console.log('Gebruik: node client.js <upload|download> <bestand> <host> <poort>');
  process.exit(1);
}
const PORT = parseInt(port, 10);

// Maak verbinding met de TCP-server
const socket = net.connect({ host, port: PORT }, () => {
  if (mode === 'upload') {
    startUpload(socket, file);
  } else if (mode === 'download') {
    startDownload(socket, file);
  }
});

// Behandel netwerkfouten centraal
socket.on('error', e => {
  console.error('Socket fout:', e.message);
});

// Functie om bestanden te uploaden naar de server
function startUpload(socket, filePath) {
  if (!fs.existsSync(filePath)) {
    console.error('Bestand niet gevonden:', filePath);
    socket.destroy();
    process.exit(1);
  }

  const data = fs.readFileSync(filePath);
  const name = path.basename(filePath);

  // Bereken een SHA-256 hash van het bestand. De server gebruikt deze om te
  // controleren of het bestand onderweg (tijdens de upload) niet is gewijzigd.
  const hash = crypto.createHash('sha256').update(data).digest('hex');

  // Metadata als JSON doorsturen
  const metadata = JSON.stringify({
    mode: 'upload',
    filename: name,
    size: data.length,
    time: Date.now(),
    hash: hash
  });

  socket.write(metadata + '\n');
  socket.write(data);
  socket.end(); // Sluit de schrijfzijde zodat de server weet dat we klaar zijn

  // Wacht op de succes-bevestiging van de server
  socket.on('data', d => {
    console.log(d.toString().trim());
    socket.end();
  });
}

// Functie om bestanden te downloaden van de server
function startDownload(socket, filePath) {
  const storagePath = path.resolve(process.cwd(), path.basename(filePath));
  const writeStream = fs.createWriteStream(storagePath);

  // Behandel schrijf-fouten naar de disk
  writeStream.on('error', err => {
    console.error('Bestandsfout:', err.message);
    socket.destroy();
    cleanupIncompleteFile();
  });

  // Stuur het downloadverzoek met metadata
  const metadata = JSON.stringify({
    mode: 'download',
    filename: filePath
  });
  socket.write(metadata + '\n');

  let fileSize = null;
  let receivedSize = 0;
  let buffer = Buffer.alloc(0);
  let expectedHash = null;
  const hash = crypto.createHash('sha256'); // Berekent de hash van de ontvangen bytes

  // Verwerk de binnenkomende bestandsdata
  socket.on('data', dataChunk => {
    if (fileSize === null) {
      buffer = Buffer.concat([buffer, dataChunk]);
      const index = buffer.indexOf(10); // 10 is de newline (\n)
      if (index === -1) return;

      const firstLine = buffer.slice(0, index).toString();
      const parts = firstLine.split(' ');

      if (parts[0] !== 'SIZE') {
        console.error('Onverwacht antwoord van server:', firstLine);
        socket.end();
        cleanupIncompleteFile();
        return;
      }

      fileSize = parseInt(parts[1], 10);
      expectedHash = parts[2] || null; // De door de server meegestuurde hash

      // Schrijf het restant na de SIZE header direct weg
      const rest = buffer.slice(index + 1);
      if (rest.length > 0) {
        writeStream.write(rest);
        hash.update(rest);
        receivedSize += rest.length;
      }
      buffer = null; // Buffer legen om geheugen te sparen
    } else {
      writeStream.write(dataChunk);
      hash.update(dataChunk);
      receivedSize += dataChunk.length;
    }

    // Controleer of de download compleet is
    if (fileSize !== null && receivedSize >= fileSize) {
      writeStream.end(() => {
        // Vergelijk de berekende hash met de hash van de server. Komt deze niet
        // overeen, dan is het bestand onderweg gewijzigd of beschadigd.
        const computedHash = hash.digest('hex');
        if (expectedHash && expectedHash !== computedHash) {
          console.error('FOUT integriteitscontrole mislukt: bestand is tijdens download gewijzigd');
          cleanupIncompleteFile();
          return;
        }
        console.log('Download voltooid. Opgeslagen in:', storagePath);
        if (expectedHash) console.log('Integriteitscontrole OK (sha256: ' + computedHash + ')');
      });
      socket.end();
    }
  });

  // Ruim het bestand op als de verbinding voortijdig sluit
  socket.on('close', () => {
    if (fileSize === null || receivedSize < fileSize) {
      cleanupIncompleteFile();
    }
  });

  function cleanupIncompleteFile() {
    writeStream.destroy();
    try {
      fs.rmSync(storagePath, { force: true });
    } catch (e) {}
  }
}

 