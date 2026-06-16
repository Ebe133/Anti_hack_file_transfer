const net = require('net');
const fs = require('fs');
const path = require('path');

const [mode, bestand, host, poort] = process.argv.slice(2);
if (!mode || !bestand || !host || !poort) {
  console.log('Gebruik: node client.js <upload|download> <bestand> <host> <poort>');
  process.exit(1);
}

if (mode === 'upload') {
  upload(bestand, host, poort);
} else if (mode === 'download') {
  download(bestand, host, poort);
} else {
  console.log('Onbekende modus: ' + mode + ' (gebruik upload of download)');
  process.exit(1);
}

function upload(bestand, host, poort) {
  const naam = path.basename(bestand);
  const socket = net.createConnection({ host, port: Number(poort), allowHalfOpen: true }, () => {
    socket.write('upload ' + naam + '\n');
    fs.createReadStream(bestand).pipe(socket);
  });
  socket.on('data', (stuk) => console.log(stuk.toString().trim()));
}

function download(bestand, host, poort) {
  const naam = path.basename(bestand);
  const socket = net.createConnection({ host, port: Number(poort) }, () => {
    socket.write('download ' + naam + '\n');
  });
  leesRegel(socket, (status, rest) => {
    if (status !== 'OK') {
      console.log(status);
      socket.end();
      return;
    }
    const doel = fs.createWriteStream(naam);
    doel.write(rest);
    socket.pipe(doel);
    doel.on('finish', () => console.log('Gedownload: ' + naam));
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
