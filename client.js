const net = require('net'); //het word gebruikt om een TCP-verbinding te maken.
const fs = require('fs'); //fs word gebruikt om bestanden te lezen en schrijven. 
const path = require('path');
//tcp-verbindingen zorgt voor communicatie tussen client en server js.
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
  const grootte = fs.statSync(bestand).size;
  const metadata = JSON.stringify({ mode: 'upload', filename: naam, size: grootte, time: Date.now() });
  const socket = net.createConnection({ host, port: Number(poort), allowHalfOpen: true }, () => {
    socket.write(metadata + '\n');
    fs.createReadStream(bestand).pipe(socket);
  });
  socket.on('data', (stuk) => console.log(stuk.toString().trim()));
  socket.on('error', (fout) => {
    console.log('Verbinding mislukt: ' + fout.message);
    process.exit(1);
  });
}

function download(bestand, host, poort) {
  const naam = path.basename(bestand);
  const metadata = JSON.stringify({ mode: 'download', filename: naam });
  const socket = net.createConnection({ host, port: Number(poort) }, () => {
    socket.write(metadata + '\n');
  });
  socket.on('error', (fout) => {
    console.log('Verbinding mislukt: ' + fout.message);
    process.exit(1);
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
