const net = require('net');
const fs = require('fs');
const path = require('path');
const bytes = require('bytes');

const poort = Number(process.argv[2]);
if (!poort) {
  console.log('Gebruik: node server.js <poort>');
  process.exit(1);
}

const ontvangMap = path.join(__dirname, 'received');
fs.mkdirSync(ontvangMap, { recursive: true });

const MAX_BESTANDSGROOTTE = bytes('10MB');
const MAX_TIJDSVERSCHIL = 60 * 1000;          // 60 seconden

let bestandOntvangen = false;

const server = net.createServer({ allowHalfOpen: true }, behandelVerbinding);
server.listen(poort, () => console.log('Server op poort ' + poort));

function behandelVerbinding(socket) {
  // Eén bestand per server: na een geslaagde upload accepteren we niets meer.
  if (bestandOntvangen) {
    socket.end('FOUT server accepteert geen uploads meer\n');
    return;
  }
  leesRegel(socket, (regel, rest) => {
    let metadata;
    try {
      metadata = JSON.parse(regel);
    } catch (fout) {
      socket.end('FOUT ongeldige metadata\n');
      return;
    }
    if (metadata.mode === 'upload') {
      const reden = valideerMetadata(metadata);
      if (reden) {
        socket.end('FOUT geweigerd: ' + reden + '\n');
        return;
      }
      ontvangUpload(socket, metadata, rest);
    } else if (metadata.mode === 'download') {
      verstuurDownload(socket, metadata.filename);
    } else {
      socket.end('FOUT onbekend commando: ' + metadata.mode + '\n');
    }
  });
}

// Controleert de metadata voor we iets accepteren. Geeft een reden terug bij afkeuring, anders null.
function valideerMetadata(metadata) {
  if (!veiligeBestandsnaam(metadata.filename)) return 'ongeldige bestandsnaam';
  if (!(metadata.size > 0) || metadata.size > MAX_BESTANDSGROOTTE) return 'bestandsgrootte ongeldig of te groot';
  if (Math.abs(Date.now() - metadata.time) > MAX_TIJDSVERSCHIL) return 'tijdstempel buiten bereik';
  return null;
}

// Blokkeert padmanipulatie zoals ../ of een absoluut pad.
function veiligeBestandsnaam(naam) {
  if (!naam) return false;
  if (naam.includes('/') || naam.includes('\\')) return false;
  if (naam.includes('..')) return false;
  return true;
}

function ontvangUpload(socket, metadata, eersteStuk) {
  const pad = path.join(ontvangMap, metadata.filename);
  const doel = fs.createWriteStream(pad);
  let ontvangen = 0;
  let afgebroken = false;

  doel.on('error', () => {}); // schrijffouten na afbreken negeren

  function verwerk(stuk) {
    if (afgebroken) return;
    ontvangen += stuk.length;
    // Vertrouw de opgegeven grootte niet blind: kap af als de echte stroom de limiet overschrijdt.
    if (ontvangen > MAX_BESTANDSGROOTTE) {
      afgebroken = true;
      socket.destroy();
      doel.destroy();
      fs.rmSync(pad, { force: true });
      console.log('Upload afgebroken: groter dan limiet');
      return;
    }
    doel.write(stuk);
  }

  verwerk(eersteStuk);
  socket.on('data', verwerk);
  socket.on('end', () => {
    doel.end(() => {
      socket.end('OK geupload: ' + metadata.filename + '\n');
      bestandOntvangen = true;
      server.close();
    });
  });
}

function verstuurDownload(socket, bestand) {
  if (!veiligeBestandsnaam(bestand)) {
    socket.end('FOUT ongeldige bestandsnaam\n');
    return;
  }
  const bron = fs.createReadStream(path.join(ontvangMap, bestand));
  bron.on('error', () => socket.end('FOUT niet gevonden: ' + bestand + '\n'));
  bron.on('open', () => {
    socket.write('OK\n');
    bron.pipe(socket);
  });
}

// Leest een regel (tot de eerste \n) uit de stream; de rest zijn al bestandsbytes.
function leesRegel(socket, klaar) {
  let buffer = Buffer.alloc(0);
  socket.on('data', function opData(stuk) {
    buffer = Buffer.concat([buffer, stuk]);
    const einde = buffer.indexOf(10);
    if (einde === -1) return;
    socket.removeListener('data', opData);
    klaar(buffer.slice(0, einde).toString(), buffer.slice(einde + 1));
  });
}
