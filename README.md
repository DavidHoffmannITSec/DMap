# Fortgeschrittener Port Scanner

Ein leistungsstarker und flexibler Portscanner, der verschiedene Scan-Techniken unterstützt, um offene Ports, Dienste und Schwachstellen auf Systemen zu entdecken. Dieses Tool bietet fortschrittliche Funktionen wie TCP/IP-Fingerprinting, Service-Erkennung, Firewall-Analyse und mehr.

## Funktionen

- **Mehrere Scan-Techniken**:
  - `-sT`: TCP-Scan
  - `-sU`: UDP-Scan
  - `-sS`: SYN-Scan
  - `-sX`: XMAS-Scan
  - `-sF`: FIN-Scan
  - `-sN`: NULL-Scan
  - `-sV`: Versions-Scan (Diensterkennung)

- **Flexible Zieldefinition**:
  - Einzelne IP-Adresse: `192.168.1.1`
  - Domain-Namen: `example.com`
  - Subnetz (CIDR): `192.168.1.0/24`
  - IP-Bereich: `192.168.1.1-192.168.1.254`

- **Port-Optionen**:
  - Spezifizieren einzelner Ports: `-p 80` oder `-p 80,443,21`
  - Scannen der Top 100 häufig genutzten Ports: `-top`
  - Scannen eines Portbereichs: `-r START END`

- **Detaillierte Dienst- und Versionsinformationen**:
  - TCP/IP-Fingerprinting zur Betriebssystemerkennung
  - Service-Banner und SSL-Zertifikatinformationen abrufen
  - DNS- und Reverse-DNS-Auflösung

- **Firewall- und IDS/IPS-Erkennung**:
  - Analyse von Zeitverzögerungen und Antwortmustern

- **Multithreading-Unterstützung**:
  - Anzahl der Threads anpassbar: `-mt`

- **Berichtserstellung**:
  - Speichern der Ergebnisse in einer Datei: `-o pfad/zur/datei.txt`

- **Aggressionsstufen (Timeout)**:
  - Einstellbare Scan-Geschwindigkeit: `-t T0-T5` (langsamer bis schneller)

- **Echtzeit-Fortschrittsanzeige**:
  - Zeigt den Fortschritt während des Scans an.

- **Verzeichnis-Scanning**:
  - Suche nach häufig genutzten Verzeichnissen wie `/admin`, `/login` oder `/config`.

