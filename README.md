DDNS Panel

Leichtgewichtiges lokales DDNS-Verwaltungspanel fuer Raspberry Pi und Linux-Server.
Ohne Docker.
Mit Login, systemd-Timer, mehreren Hostnamen pro Dienst und Netcup-REST-Unterstuetzung.

Funktionen
- lokales Web-Panel mit Login
- Dashboard fuer oeffentliche IP und Update-Status
- mehrere DDNS-Eintraege
- mehrere Hostnamen pro Dienst, jeweils eine Domain pro Zeile
- Provider-Abstraktion mit Netcup REST API, Dynu und weiteren Anbietern
- Netcup API-Key einmal hinterlegen und mehrere Zonen-Hostnamen aktualisieren
- globale Setup-Seite fuer Timer-, Retry- und IP-Quellen
- zentraler systemd-Timer fuer alle Eintraege
- mDNS-Name `ddns-panel.local`
- optional lokaler Reverse Proxy ueber vorhandenen Nginx Proxy Manager

Installation
```bash
cd /home/wolf/ddns-panel
sudo ./install.sh
```

Danach:
- Direkt: `http://SERVER-IP:5085`
- Lokal: `http://ddns-panel.local` oder `http://ddns-panel.local:5085`
