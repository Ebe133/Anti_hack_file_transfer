const net = require('net');
const fs = require('fs');
const path = require('path');

// You need all four things after "node client.js". If any are missing, show how
// to use it and stop.
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
  // Just send the file's name, not the full path on your computer. That way the
  // server never finds out how your folders are laid out.
  const naam = path.basename(bestand);
  // Tell the server how big the file is so it knows how much to wait for.
  const grootte = fs.statSync(bestand).size;
  // First you send one line describing the file, then the file itself. It uses
  // JSON for that line so it's easy to add more details later if you need to.
  const metadata = JSON.stringify({ mode: 'upload', filename: naam, size: grootte, time: Date.now() });

  // allowHalfOpen lets you keep listening after you're done sending. Without it,
  // the connection would close the moment the file finishes and you'd miss the
  // server's "done" message.
  const socket = net.createConnection({ host, port: Number(poort), allowHalfOpen: true }, () => {
    socket.write(metadata + '\n');
    // Send the file piece by piece instead of loading it all into memory, so
    // even a huge file goes through fine.
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
  // The server first sends a short status message, then the file. Read that
  // message first.
  leesRegel(socket, (status, rest) => {
    if (status !== 'OK') {
      console.log(status);
      socket.end();
      return;
    }
    const doel = fs.createWriteStream(naam);
    // Sometimes a bit of the file arrives together with the status message.
    // Save that leftover bit first, then let the rest stream in.
    doel.write(rest);
    socket.pipe(doel);
    doel.on('finish', () => console.log('Gedownload: ' + naam));
  });
}

// Reads the first line of what the server sends; everything after it is the
// file. The data doesn't always arrive in neat pieces: one delivery might hold
// only part of the line, or the whole line plus a chunk of the file. So it keeps
// collecting until it spots the end of the line.
function leesRegel(socket, klaar) {
  // Collect the incoming data as raw bytes and keep adding to it. It holds off on
  // turning it into text, because the file can contain anything and a character
  // could get split across two deliveries and come out garbled. It only turns the
  // first line into text once it has the whole line.
  let buffer = Buffer.alloc(0);
  socket.on('data', function opData(stuk) {
    buffer = Buffer.concat([buffer, stuk]);
    // 10 is the code for the "new line" character. Keep waiting until we see one.
    const einde = buffer.indexOf(10);
    if (einde === -1) return;
    // Stop listening here so the file-saving code below gets all the rest of the
    // data, instead of both handlers grabbing at it.
    socket.removeListener('data', opData);
    klaar(buffer.slice(0, einde).toString(), buffer.slice(einde + 1));
  });
}
