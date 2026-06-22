const net = require('net');
const fs = require('fs');
const path = require('path');

// Eenvoudige TCP file server: ondersteunt upload en download via een korte JSON
// metadata-regel gevolgd door raw bytes. Dit is bedoeld als minimale, werkende
// implementatie die bij `client.js` past.

const PORT = parseInt(process.argv[2], 10) || 8000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const server = net.createServer((socket) => {
  // Lees één regel metadata (JSON) en behandel daarna de rest afhankelijk van mode
  readLine(socket, (metaLine, rest) => {
    let meta;
    try {
      meta = JSON.parse(metaLine);
    } catch (e) {
      socket.write('ERROR invalid metadata\n');
      socket.end();
      return;
    }

    if (meta.mode === 'upload') {
      handleUpload(socket, meta, rest);
    } else if (meta.mode === 'download') {
      handleDownload(socket, meta);
    } else {
      socket.write('ERROR unknown mode\n');
      socket.end();
    }
  });
});

// Start de server
server.listen(PORT, () => console.log('Server luistert op poort', PORT));

// Handle upload: schrijf precies `meta.size` bytes naar bestand
function handleUpload(socket, meta, rest) {
  const filename = path.basename(String(meta.filename || 'upload.bin'));
  const size = Number(meta.size) || 0;
  const outPath = path.join(UPLOAD_DIR, filename);
  const ws = fs.createWriteStream(outPath);
  let received = 0;

  // Schrijf eventueel reeds ontvangen bytes
  if (rest && rest.length) {
    ws.write(rest);
    received += rest.length;
  }

  // Schrijf verdere binnenkomende data totdat we genoeg bytes hebben
  socket.on('data', (chunk) => {
    const remaining = size - received;
    if (remaining <= 0) return;
    if (chunk.length > remaining) {
      ws.write(chunk.slice(0, remaining));
      received += remaining;
    } else {
      ws.write(chunk);
      received += chunk.length;
    }

    if (received >= size) {
      ws.end();
      socket.write('OK\n');
      // Let client sluiten; we keep socket open briefly for the ACK to be sent
    }
  });

  socket.on('end', () => ws.end());
  socket.on('error', () => ws.end());
}

// Handle download: stuur 'OK' en pipe het bestand naar de socket
function handleDownload(socket, meta) {
  const filename = path.basename(String(meta.filename || ''));
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) {
    socket.write('ERROR file not found\n');
    socket.end();
    return;
  }
  socket.write('OK\n');
  const rs = fs.createReadStream(filePath);
  rs.pipe(socket);
  rs.on('end', () => socket.end());
  rs.on('error', () => socket.end());
}

// Helper: lees tot en met eerste newline. Geeft de lijn (zonder \n) en rest-buffer terug
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
