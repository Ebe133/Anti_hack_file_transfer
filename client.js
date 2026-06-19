const net = require('net');
const fs = require('fs');
const path = require('path');

// Lees de parameters: upload/download, bestandspad, host en poort (bijv. node client.js upload test.txt localhost 8080)
const [modus, bestand, host, poort] = process.argv.slice(2);
if (!modus || !bestand || !host || !poort || (modus !== 'upload' && modus !== 'download')) {
  console.log('Gebruik: node client.js <upload|download> <bestand> <host> <poort>');
  process.exit(1);
}
const PORT = parseInt(poort, 10);

// Maak verbinding met de TCP-server
const socket = net.connect({ host, port: PORT }, () => {
  if (modus === 'upload') {
    startUpload(socket, bestand);
  } else if (modus === 'download') {
    startDownload(socket, bestand);
  }
});

// Behandel netwerkfouten centraal
socket.on('error', e => {
  console.error('Socket fout:', e.message);
});

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

function startDownload(socket, bestandspad) {}

