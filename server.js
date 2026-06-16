const net = require('net');
const fs = require('fs');
const path = require('path');

// Poort: optioneel argument, standaard 8000
const PORT = process.argv[2] ? parseInt(process.argv[2]) : 8000;
const STORAGE_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

const server = net.createServer(socket => {
  console.log('Client verbonden');
  let pending = null; // {type, filename, size, received, chunks}
  let buffer = Buffer.alloc(0);

  socket.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    processBuffer();
  });

  function processBuffer() {
    if (!pending) {
      const idx = buffer.indexOf('\n');
      if (idx === -1) return; // wacht op volledige regel
      const line = buffer.slice(0, idx).toString().trim();
      buffer = buffer.slice(idx + 1);
      const parts = line.split(' ');
      const cmd = parts[0].toUpperCase();

      if (cmd === 'UPLOAD' && parts.length === 3) {
        const filename = path.basename(parts[1]);
        const size = parseInt(parts[2], 10);
        pending = { type: 'upload', filename, size, received: 0, chunks: [] };
        processBuffer(); // recursief voor eventuele restdata
      } else if (cmd === 'DOWNLOAD' && parts.length === 2) {
        const filename = path.basename(parts[1]);
        const filePath = path.join(STORAGE_DIR, filename);
        if (!fs.existsSync(filePath)) {
          socket.write('ERROR NotFound\n');
          socket.end();
          return;
        }
        const stat = fs.statSync(filePath);
        socket.write(`SIZE ${stat.size}\n`);
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(socket);
        readStream.on('end', () => socket.end());
      } else {
        socket.write('ERROR UnknownCommand\n');
        socket.end();
      }
    } else if (pending.type === 'upload') {
      const remaining = pending.size - pending.received;
      const chunk = buffer.slice(0, remaining);
      pending.chunks.push(chunk);
      pending.received += chunk.length;
      buffer = buffer.slice(chunk.length);
      if (pending.received === pending.size) {
        const fileData = Buffer.concat(pending.chunks);
        const filePath = path.join(STORAGE_DIR, pending.filename);
        fs.writeFileSync(filePath, fileData);
        socket.write('OK\n');
        pending = null;
        processBuffer();
      }
    }
  }

  socket.on('end', () => console.log('Client verbroken'));
  socket.on('error', err => console.error('Socket fout:', err));
});

server.listen(PORT, () => console.log(`Eenvoudige server luistert op poort ${PORT}`));
