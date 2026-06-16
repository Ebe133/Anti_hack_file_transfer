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

// Functie om bestanden te downloaden van de server
function startDownload(socket, bestandspad) {
  const opslagPad = path.resolve(process.cwd(), path.basename(bestandspad));
  const schrijfStream = fs.createWriteStream(opslagPad);

  // Behandel schrijf-fouten naar de disk
  schrijfStream.on('error', err => {
    console.error('Bestandsfout:', err.message);
    socket.destroy();
    ruimIncompleetBestandOp();
  });

  // Stuur het downloadverzoek met metadata
  const metadata = JSON.stringify({ 
    mode: 'download', 
    filename: bestandspad 
  });
  socket.write(metadata + '\n');

  let bestandGrootte = null;
  let ontvangenGrootte = 0;
  let buffer = Buffer.alloc(0);

  // Verwerk de binnenkomende bestandsdata
  socket.on('data', dataBlok => {
    if (bestandGrootte === null) {
      buffer = Buffer.concat([buffer, dataBlok]);
      const index = buffer.indexOf(10); // 10 is de newline (\n)
      if (index === -1) return;

      const eersteRegel = buffer.slice(0, index).toString();
      const delen = eersteRegel.split(' ');

      if (delen[0] !== 'SIZE') {
        console.error('Onverwacht antwoord van server:', eersteRegel);
        socket.end();
        ruimIncompleetBestandOp();
        return;
      }

      bestandGrootte = parseInt(delen[1], 10);
      
      // Schrijf het restant na de SIZE header direct weg
      const rest = buffer.slice(index + 1);
      if (rest.length > 0) {
        schrijfStream.write(rest);
        ontvangenGrootte += rest.length;
      }
      buffer = null; // Buffer legen om geheugen te sparen
    } else {
      schrijfStream.write(dataBlok);
      ontvangenGrootte += dataBlok.length;
    }

    // Controleer of de download compleet is
    if (bestandGrootte !== null && ontvangenGrootte >= bestandGrootte) {
      schrijfStream.end(() => {
        console.log('Download voltooid. Opgeslagen in:', opslagPad);
      });
      socket.end();
    }
  });

  // Ruim het bestand op als de verbinding voortijdig sluit
  socket.on('close', () => {
    if (bestandGrootte === null || ontvangenGrootte < bestandGrootte) {
      ruimIncompleetBestandOp();
    }
  });

  function ruimIncompleetBestandOp() {
    schrijfStream.destroy();
    try {
      fs.rmSync(opslagPad, { force: true });
    } catch (e) {}
  }
}
