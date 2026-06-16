# Simple File Transfer

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
