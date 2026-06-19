# Nexus Share - P2P File Transfer over I2P

Een anonieme, veilige P2P bestandsoverdracht applicatie via het I2P-netwerk met een moderne Web UI.

## Hoe het werkt

1. **Web UI & Backend (Node.js)**: Draait op poort `3000`. Hiermee beheer je de applicatie in de browser.
2. **Directory & Auth Server (PHP)**: Draait op poort `8000` en zorgt voor anonieme peer-lookup en registratie/inlog.
3. **I2P Netwerk (i2pd)**: Start automatisch op de achtergrond. Zorgt voor volledige anonimiteit en versleuteling via I2P-tunnels.

---

## Vereisten

Zorg dat je **Node.js** en **PHP** (met de `sockets` extensie ingeschakeld) op je computer hebt geïnstalleerd.

---

## Starten

Open een terminal in de projectmap en voer het volgende commando uit:

```bash
node p2p.js
```

Dit start automatisch:
- De Node.js HTTP server (poort 3000)
- De PHP Auth & Directory Server (poort 8000)
- De I2P-daemon op de achtergrond (kan tot 2 minuten duren bij de eerste keer opstarten; keur eventuele admin-/firewall-meldingen goed)

---

## Gebruik

1. Open **[http://localhost:3000](http://localhost:3000)** in je browser.
2. Ga naar de **Register** tab om een account aan te maken.
3. Log in via de **Login** tab. Je krijgt nu een uniek I2P-adres (bijvoorbeeld `.b32.i2p`).
4. Om bestanden te versturen, vul het I2P-adres van de ontvanger in en selecteer het bestand.
