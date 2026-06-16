# Anti_hack_file_transfer
# Bestandstransfersysteem met Beveiliging

## Projectbeschrijving
Dit project is een beveiligd bestandstransfersysteem waarmee bestanden tussen een client en server worden verstuurd. onze focus ligt op veilige communicatie, authenticatie en databeveiliging tijdens transport. 

## Doel van het project
Het doel is om een systeem te bouwen dat bestanden veilig kan verzenden met aandacht voor:
- Bescherming tegen ongeautoriseerde toegang
- Integriteit van bestanden
- Encryptie tijdens transport
- Logging van overdrachten

## Functionaliteiten
- Bestanden verzenden van client naar server
- Veilige opslag op de server
- Authenticatie van gebruikers of systemen
- Encryptie van bestanden tijdens verzending
- Logging van transfers
- Foutafhandeling bij mislukte overdrachten

## Security
Het systeem houdt rekening met de volgende beveiligingsaspecten:

### Beveiliging
- Encryptie van data tijdens transport
- Authenticatie van client en server
- Controle van bestandsintegriteit (hashing)
- Logging van alle bestandsoverdrachten

### Bedreigingen
- Man-in-the-middle aanvallen
- Ongeautoriseerde toegang
- Manipulatie van bestanden
- Afluisteren van data

## Architectuur
Het systeem bestaat uit:

### Client
- Verstuurt bestanden
- Versleutelt data
- Maakt verbinding met server

### Server
- Ontvangt bestanden
- Controleert authenticatie
- Slaat bestanden op
- Logt activiteiten

### Communicatie
- Beveiligde verbinding via netwerkprotocol (bijv. TCP/HTTPS)

## Technische keuzes
- Programmeertaal: js / 
- Protocol: TCP of HTTPS
- Encryptie: AES + RSA
- Hashing: SHA-256
- Opslag: File system of database

## Projectstructuur
/project-root
- client/
- server/
- docs/
  - probleemanalyse.md
  - security-requirements.md
  - architectuur.mda
  - technische-keuzes.md
- README.md

## Scrum planning
Het project gebruikt een Scrum-board met:
- Backlog
- To Do
- Doing
- Done



