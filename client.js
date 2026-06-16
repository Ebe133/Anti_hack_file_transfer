const net = require('net');
const fs = require('fs');
const path = require('path');

// Gebruik: node client.js <upload|download> <bestand> <host> <poort>
const [mode, bestand, host, poort] = process.argv.slice(2);
if (!mode || !bestand || !host || !poort) {
  console.log('Gebruik: node client.js <upload|download> <bestand> <host> <poort>');
  process.exit(1);
}
const PORT = parseInt(poort, 10);

if (mode === 'upload') {
  if (!fs.existsSync(bestand)) {
    console.error('Bestand niet gevonden:', bestand);
    process.exit(1);
  }
  const data = fs.readFileSync(bestand);
  const naam = path.basename(bestand);
  const socket = net.connect({ host, port: PORT }, () => {
    socket.write(`UPLOAD ${naam} ${data.length}\n`);
    socket.write(data);
  });
  socket.on('data', d => {
    console.log(d.toString().trim());
    socket.end();
  });
  socket.on('error', e => console.error('Socket fout:', e));
} else if (mode === 'download') {
  const socket = net.connect({ host, port: PORT }, () => {
    socket.write(`DOWNLOAD ${bestand}\n`);
  });
  let grootte = null;
  let buffer = Buffer.alloc(0);
  const out = fs.createWriteStream(path.basename(bestand));
  socket.on('data', d => {
    if (grootte === null) {
      const idx = d.indexOf('\n');
      if (idx === -1) return;
      const line = d.slice(0, idx).toString();
      const parts = line.split(' ');
      if (parts[0] !== 'SIZE') {
        console.error('Onverwacht antwoord:', line);
        socket.end();
        return;
      }
      grootte = parseInt(parts[1], 10);
      buffer = Buffer.concat([buffer, d.slice(idx + 1)]);
    } else {
      buffer = Buffer.concat([buffer, d]);
    }
    if (grootte !== null && buffer.length >= grootte) {
      out.write(buffer.slice(0, grootte));
      out.end();
      console.log('Download voltooid');
      socket.end();
    }
  });
  socket.on('error', e => console.error('Socket fout:', e));
} else {
  console.error('Onbekende modus:', mode);
  process.exit(1);
}
