const net = require('net');
const fs = require('fs');
const path = require('path');

const poort = Number(process.argv[2]);
if (!poort) {
  console.log('Gebruik: node server.js <poort>');
  process.exit(1);
}

const ontvangMap = path.join(__dirname, 'received');
fs.mkdirSync(ontvangMap, { recursive: true });

const server = net.createServer({ allowHalfOpen: true }, behandelVerbinding);
server.listen(poort, () => console.log('Server op poort ' + poort));

function behandelVerbinding(socket) {
  leesRegel(socket, (regel, rest) => {
    const [mode, bestand] = regel.split(' ');
    if (mode === 'upload') {
      ontvangUpload(socket, bestand, rest);
    } else if (mode === 'download') {
      verstuurDownload(socket, bestand);
    } else {
      socket.end('FOUT onbekend commando: ' + mode + '\n');
    }
  });
}

function ontvangUpload(socket, bestand, eersteStuk) {
  const doel = fs.createWriteStream(path.join(ontvangMap, bestand));
  doel.write(eersteStuk);
  socket.pipe(doel);
  doel.on('finish', () => socket.end('OK geüpload: ' + bestand + '\n'));
}

function verstuurDownload(socket, bestand) {
  const bron = fs.createReadStream(path.join(ontvangMap, bestand));
  bron.on('error', () => socket.end('FOUT niet gevonden: ' + bestand + '\n'));
  bron.on('open', () => {
    socket.write('OK\n');
    bron.pipe(socket);
  });
}

// Leest één regel (tot de eerste \n) uit de stream; de rest zijn al bestandsbytes.
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
