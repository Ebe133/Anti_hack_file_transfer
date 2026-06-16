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
