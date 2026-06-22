# Anti-hack File Transfer — eenvoudig lokaal

Kort: deze kleine repo bevat een Node `client.js` en een bijbehorende `server.js` voor eenvoudige file upload/download via TCP.

Bestanden
- `client.js` — client voor upload/download (gebruiksvriendelijk, met comments)
- `server.js` — eenvoudige Node TCP server die hetzelfde protocol ondersteunt
- `uploads/` — map waar geüploade bestanden worden opgeslagen

Protocol
- De client stuurt eerst één JSON-regel gevolgd door een newline (`\n`).
- Daarna volgen de raw file-bytes (voor uploads) of de server stuurt raw bytes (voor downloads).
- Voor upload: metadata = `{ "mode":"upload", "filename":"naam", "size":1234 }`
- Voor download: metadata = `{ "mode":"download", "filename":"naam" }`

Start de server

```bash
node server.js 8000
```

Upload een bestand

```bash
node client.js upload pad/naar/bestand localhost 8000
```

Download een bestand (naam moet bestaan in `uploads/` op de server)

```bash
node client.js download bestandsnaam localhost 8000
```

Opmerkingen
- Dit is een minimale demo: er is geen encryptie of authenticatie.
- De server vertrouwt op `meta.size` voor uploads — zorg dat de client de juiste grootte doorstuurt.
- Als je liever met `server.php` wilt werken kan ik `client.js` aanpassen zodat het met die PHP-server praat.

Wil je dat ik nu lokaal de server start en een testupload uitvoer? Geef toestemming en ik voer het uit en rapporteer de output.
# Simple File Transfer

## Server
```bash
# Start de server (poort optioneel, standaard 8000)
node simple_transfer/server.js [poort]
```

## Client
```bash
# Upload een bestand
node simple_transfer/client.js upload <bestand> <host> <poort>

# Download een bestand
node simple_transfer/client.js download <bestand> <host> <poort>
```
