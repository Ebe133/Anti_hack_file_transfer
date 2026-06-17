# Simple File Transfer

Een eenvoudige bestandsoverdracht over een rauwe TCP-verbinding, geschreven in Node.js.
De ontvanger (`server.js`) draait als TCP-server en de verzender (`client.js`) maakt
verbinding om een bestand te **uploaden** of te **downloaden**.

Beide kanten zijn dus eigenlijk een soort client; de "server" is alleen de ontvangende
partij die luistert, terwijl de client degene is die de actie start.

## Hoe het werkt

- De client stuurt eerst één regel JSON-metadata (`mode`, `filename`, `size`, `time`),
  gevolgd door de ruwe bestandsinhoud.
- De server leest die eerste regel, valideert deze en streamt het bestand vervolgens
  naar de map `received/` (bij upload) of leest het er weer uit (bij download).
- Bestanden worden gestreamd in plaats van volledig in het geheugen geladen, zodat ook
  grotere bestanden verwerkt kunnen worden.

## Beveiliging (anti-hack)

Het project legt de nadruk op het veilig afhandelen van onbetrouwbare input:

- **Path traversal-bescherming** — bestandsnamen met `/`, `\` of `..` worden geweigerd,
  zodat een client niet buiten de `received/`-map kan schrijven of lezen.
- **Replay-bescherming** — de tijdstempel in de metadata mag maximaal 60 seconden
  afwijken van de servertijd.
- **Groottelimiet** — bestanden tot 10MB worden automatisch geaccepteerd; grotere
  uploads vragen handmatig om toestemming in de serverconsole. Wie meer data stuurt dan
  is afgesproken, wordt direct afgebroken en het halve bestand wordt opgeruimd.
- **Robuuste foutafhandeling** — socket- en schijffouten laten de server niet crashen en
  onvolledige bestanden worden netjes verwijderd.

## Vereisten

- [Node.js](https://nodejs.org/)
- Het npm-pakket [`bytes`](https://www.npmjs.com/package/bytes):

```bash
npm install bytes
```

# How to run
## Server
```bash
# Start de server (poort optioneel, standaard 8000)
node server.js [poort]
```

## Client
```bash
# Upload een bestand
node client.js upload <bestand> <host> <poort>

# Download een bestand
node client.js download <bestand> <host> <poort>
```
(both are kind of a client just sever is to reciever client is sender)
