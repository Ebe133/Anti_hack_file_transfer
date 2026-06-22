const net = require('net');
const fs = require('fs');
const path = require('path');


const args = process.argv.slice(2);
const modus = args[0];
if (!modus) {
  console.log('Gebruik: zie source header voor beschikbare modes');
  process.exit(1);
}

// Router per mode
if (modus === 'upload' || modus === 'download') {
  const bestand = args[1];
  const host = args[2];
  const poort = args[3];
  if (!bestand || !host || !poort) {
    console.log('Gebruik: node client.js ' + modus + ' <bestand> <host> <poort>');
    process.exit(1);
  }
  const PORT = parseInt(poort, 10);
  const socket = net.connect({ host, port: PORT }, () => {
    if (modus === 'upload') startUpload(socket, bestand);
    else startDownload(socket, bestand);
  });
  socket.on('error', e => console.error('Socket fout:', e.message));

} else if (modus === 'register') {
  const username = args[1];
  const password = args[2];
  const host = args[3];
  const poort = args[4];
  if (!username || !password || !host || !poort) {
    console.log('Gebruik: node client.js register <username> <password> <host> <poort>');
    process.exit(1);
  }
  sendJsonAction(host, parseInt(poort,10), { action: 'register', username, password }, res => console.log(res));

} else if (modus === 'login') {
  const username = args[1];
  const password = args[2];
  const address = args[3];
  const host = args[4];
  const poort = args[5];
  if (!username || !password || !address || !host || !poort) {
    console.log('Gebruik: node client.js login <username> <password> <address> <host> <poort>');
    process.exit(1);
  }
  sendJsonAction(host, parseInt(poort,10), { action: 'login', username, password, address }, res => console.log(res));

} else if (modus === 'lookup') {
  const token = args[1];
  const target = args[2];
  const host = args[3];
  const poort = args[4];
  if (!token || !target || !host || !poort) {
    console.log('Gebruik: node client.js lookup <session_token> <target> <host> <poort>');
    process.exit(1);
  }
  sendJsonAction(host, parseInt(poort,10), { action: 'lookup', session_token: token, target }, res => console.log(res));

} else {
  console.log('Onbekende modus:', modus);
  process.exit(1);
}

// Functie om bestanden te uploaden naar de server
function startUpload(socket, bestandspad) {
  if (!fs.existsSync(bestandspad)) {
    console.error('Bestand niet gevonden:', bestandspad);
    socket.destroy();
    process.exit(1);
  }

  const data = fs.readFileSync(bestandspad);
  const naam = path.basename(bestandspad);

  // Metadata als JSON doorsturen
  const metadata = JSON.stringify({ 
    mode: 'upload', 
    filename: naam, 
    size: data.length, 
    time: Date.now() 
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

// Start een download: vraagt het bestand aan en slaat het lokaal op.
function startDownload(socket, requestedPath) {
  const naam = path.basename(requestedPath);
  const metadata = JSON.stringify({ mode: 'download', filename: naam });
  socket.write(metadata + '\n');

  // Lees de eerste regel (status) en bewaar eventueel restbytes van het bestand
  readLine(socket, (status, rest) => {
    if (status !== 'OK') {
      console.error('Server fout:', status);
      socket.end();
      return;
    }
    const out = fs.createWriteStream(naam);
    if (rest && rest.length) out.write(rest);
    socket.on('data', d => out.write(d));
    socket.on('end', () => {
      out.end();
      console.log('Gedownload:', naam);
    });
  });
}

// Helper: lees één regel (tot en met '\n') van de socket, geef de rest als Buffer terug.
function readLine(socket, cb) {
  let buffer = Buffer.alloc(0);
  function onData(chunk) {
    buffer = Buffer.concat([buffer, chunk]);
    const idx = buffer.indexOf(10); // '\n'
    if (idx === -1) return;
    socket.removeListener('data', onData);
    const line = buffer.slice(0, idx).toString();
    const rest = buffer.slice(idx + 1);
    cb(line, rest);
  }
  socket.on('data', onData);
}

// Stuur een JSON actie naar een PHP-server (server.php) en lees de JSON-antwoordregel
function sendJsonAction(host, port, payload, cb) {
  const socket = net.connect({ host, port }, () => {
    socket.write(JSON.stringify(payload) + '\n');
  });
  socket.on('error', e => {
    cb({ status: 'error', message: e.message });
  });
  readLine(socket, (line) => {
    let parsed = line;
    try { parsed = JSON.parse(line); } catch (e) {}
    cb(parsed);
    socket.end();
  });
}


