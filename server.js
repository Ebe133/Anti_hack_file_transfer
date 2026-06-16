const net = require('net');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const bytes = require('bytes'); // turns human sizes like '10MB' into a byte count

const poort = Number(process.argv[2]);
if (!poort) {
  console.log('Gebruik: node server.js <poort>');
  process.exit(1);
}

// Everything lands in a "received" folder next to this script. recursive makes
// it a no-op if the folder already exists.
const ontvangMap = path.join(__dirname, 'received');
fs.mkdirSync(ontvangMap, { recursive: true });

const AUTO_BESTANDSGROOTTE = bytes('10MB');    // up to this size: accepted automatically
const MAX_TIJDSVERSCHIL = 60 * 1000;          // 60 seconden: accepted automatically

// This server only ever accepts a single upload, then shuts itself down.
let bestandOntvangen = false;

// allowHalfOpen lets the server keep writing the reply after the client signals
// it's done sending, which is exactly how the upload handshake ends.
const server = net.createServer({ allowHalfOpen: true }, behandelVerbinding);
server.listen(poort, () => console.log('Server op poort ' + poort));

function behandelVerbinding(socket) {
  // Eén bestand per server: na een geslaagde upload accepteer je niets meer.
  if (bestandOntvangen) {
    socket.end('FOUT server accepteert geen uploads meer\n');
    return;
  }
  leesRegel(socket, (regel, rest) => {
    let metadata;
    try {
      metadata = JSON.parse(regel);
    } catch (fout) {
      // Anything that isn't valid JSON gets rejected before it touches the disk.
      socket.end('FOUT ongeldige metadata\n');
      return;
    }
    if (metadata.mode === 'upload') {
      const reden = valideerMetadata(metadata);
      if (reden) {
        socket.end('FOUT geweigerd: ' + reden + '\n');
        return;
      }
      // Files up to AUTO_BESTANDSGROOTTE go through automatically. Anything bigger
      // is allowed too, but only after the person running the server says yes; once
      // approved there's no upper size limit. The leftover bytes are handed over as
      // the first slice of the file.
      if (metadata.size > AUTO_BESTANDSGROOTTE) {
        vraagToestemming(metadata, (akkoord) => {
          if (!akkoord) {
            socket.end('FOUT geweigerd: ontvanger heeft de upload afgewezen\n');
            return;
          }
          ontvangUpload(socket, metadata, rest, Infinity);
        });
      } else {
        ontvangUpload(socket, metadata, rest, AUTO_BESTANDSGROOTTE);
      }
    } else if (metadata.mode === 'download') {
      verstuurDownload(socket, metadata.filename);
    } else {
      socket.end('FOUT onbekend commando: ' + metadata.mode + '\n');
    }
  });
}

// Validates the metadata before anything is accepted. Returns a reason on rejection, else null.
function valideerMetadata(metadata) {
  if (!veiligeBestandsnaam(metadata.filename)) return 'ongeldige bestandsnaam';
  // No upper bound here: large files aren't rejected, they're sent for approval.
  if (!(metadata.size > 0)) return 'bestandsgrootte ongeldig';
  // Reject stale or future timestamps; loosely guards against replayed uploads.
  if (Math.abs(Date.now() - metadata.time) > MAX_TIJDSVERSCHIL) return 'tijdstempel buiten bereik';
  return null;
}

// Asks the person running the server whether to accept an oversized upload.
// Replies with true only when they answer yes (j/ja/y/yes).
function vraagToestemming(metadata, klaar) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const vraag = 'Upload "' + metadata.filename + '" is ' + bytes(metadata.size) +
    ' (groter dan ' + bytes(AUTO_BESTANDSGROOTTE) + '). Accepteren? (j/n) ';
  rl.question(vraag, (antwoord) => {
    rl.close();
    klaar(/^(j|ja|y|yes)$/i.test(antwoord.trim()));
  });
}

// Blocks path tricks like ../ or an absolute path, so a filename can't escape
// the received folder.
function veiligeBestandsnaam(naam) {
  if (!naam) return false;
  if (naam.includes('/') || naam.includes('\\')) return false;
  if (naam.includes('..')) return false;
  return true;
}

function ontvangUpload(socket, metadata, eersteStuk, limiet) {
  const pad = path.join(ontvangMap, metadata.filename);
  const doel = fs.createWriteStream(pad);
  let ontvangen = 0;
  let afgebroken = false;

  doel.on('error', () => {}); // swallow write errors once things have been torn down

  function verwerk(stuk) {
    if (afgebroken) return;
    ontvangen += stuk.length;
    // Don't trust the size the client claimed. Count the real bytes and cut the
    // upload off the moment it goes over the agreed limit, deleting the partial
    // file. After approval the limit is Infinity, so this never trips.
    if (ontvangen > limiet) {
      afgebroken = true;
      socket.destroy();
      doel.destroy();
      fs.rmSync(pad, { force: true });
      console.log('Upload afgebroken: groter dan limiet');
      return;
    }
    doel.write(stuk);
  }

  // Process the bytes that came in alongside the metadata, then the live stream.
  verwerk(eersteStuk);
  socket.on('data', verwerk);
  socket.on('end', () => {
    // Wait for the file to finish flushing before confirming, then lock the
    // server down so it won't take another upload.
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
  // A missing file surfaces here as a read error rather than crashing.
  bron.on('error', () => socket.end('FOUT niet gevonden: ' + bestand + '\n'));
  // Only announce OK once the file actually opened, then stream it out.
  bron.on('open', () => {
    socket.write('OK\n');
    bron.pipe(socket);
  });
}

// Reads one line (up to the first newline); everything after it is file data.
// TCP has no message boundaries, so a single data event might hold half a line,
// or the whole line plus a piece of the file. It buffers until the newline shows up.
function leesRegel(socket, klaar) {
  // Empty buffer to append onto. It stays on raw bytes instead of a string so a
  // multi-byte character split across chunks can't get mangled; only the line
  // part gets decoded to text once it's complete.
  let buffer = Buffer.alloc(0);
  socket.on('data', function opData(stuk) {
    buffer = Buffer.concat([buffer, stuk]);
    const einde = buffer.indexOf(10); // 10 = newline byte
    if (einde === -1) return;
    // Detach so the upload/download handler gets every chunk from here on.
    socket.removeListener('data', opData);
    klaar(buffer.slice(0, einde).toString(), buffer.slice(einde + 1));
  });
}
