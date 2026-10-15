# IDR Investigation Analyzer

Ein kompakter, dateibasierter Analyzer für Rapid7-Investigation-Logs und angebundene Sicherheitsquellen. JSON- oder NDJSON-Daten werden lokal durch PHP ausgewertet, fachlich normalisiert und in einer übersichtlichen Investigation-Ansicht dargestellt.

## Funktionen

- verarbeitet JSON, JSON-Arrays und NDJSON
- erkennt eingebettetes JSON in Connector-Feldern
- normalisiert abweichende Feldnamen über `data.json`
- erkennt Ereignisse, Quellen, Benutzer, Systeme, IP-Adressen, Tenants und Ressourcen
- bewertet relevante Treffer mit Score und Schweregrad
- zeigt Startansicht ohne Navigationsleiste mittig an
- zeigt nach der Auswertung nur die Investigation mit relevanten Informationen
- speichert keine Investigation serverseitig
- übernimmt die komprimierte Investigation in den URL-Parameter `?inv=`
- behält die Auswertung beim Aktualisieren oder Teilen der URL bei
- entfernt die Investigation über das Papierkorb-Symbol

## Dateien

```text
index.php
├── lädt data.json
├── verarbeitet die Investigation
├── erzeugt die Ergebnisansicht
└── verwaltet den URL-Parameter ?inv=

data.json
├── Feldaliase
├── Ereigniskatalog
├── Produkt- und Quellenerkennung
├── Risikoregeln
└── Schweregrade

favicon.svg
└── optionales Browser-Favicon
```

## Voraussetzungen

- Webserver mit PHP 8.1 oder neuer
- aktivierte PHP-Erweiterung `zlib`
- Schreibzugriff ist nicht erforderlich
- JavaScript ist nicht erforderlich

Geeignete Umgebungen sind beispielsweise Apache 2.4 mit `mod_php` oder PHP-FPM sowie Nginx mit PHP-FPM.

## Installation

1. Inhalt des ZIP-Archivs in ein Webverzeichnis entpacken.
2. Sicherstellen, dass `index.php` und `data.json` im selben Verzeichnis liegen.
3. Das Verzeichnis über den Webserver aufrufen.
4. Rapid7-Investigation als JSON oder NDJSON einfügen.
5. **AUSWERTEN** auswählen.

Beispiel:

```text
/var/www/html/idr-investigation-analyzer/
├── index.php
├── data.json
├── favicon.svg
└── README.md
```

## Bedienung

### Neue Investigation

Die Startseite enthält ausschließlich:

1. `IDR Investigation Analyzer`
2. das Eingabefeld
3. den Button `AUSWERTEN`

Der Eingabeblock ist mittig auf der Seite ausgerichtet. Überschrift und Eingabefeld besitzen dieselbe linke Kante.

### Ergebnisansicht

Die Ergebnisansicht zeigt kompakt:

- Ereignis, Risikostufe und Score
- Quelle und Zeitpunkt
- beteiligte Benutzer und Konten
- Systeme, Geräte, Hosts und IP-Adressen
- Dateien, URLs, Domains, Prozesse und Ressourcen
- Dienst, Status, Standort, Tenant und Erkennungsregel
- priorisierte Bewertungstreffer

Die Ergebnisansicht enthält keine Navigationsleiste und keinen wiederholten Produkttitel. Das Papierkorb-Symbol oben rechts entfernt `?inv=` und öffnet wieder die leere Startseite.

## URL-Verhalten

Die eingegebene Investigation wird mit DEFLATE komprimiert und als Base64URL-Zeichenfolge ohne Padding in `?inv=` gespeichert.

```text
https://example.org/analyzer/?inv=KOMPRIMIERTE_DATEN
```

Dadurch werden keine Logs in Dateien, Datenbanken oder Sessions gespeichert. Sehr große Investigation-Bundles können dennoch URL-Grenzen von Browsern, Reverse Proxys oder Webservern überschreiten. Für umfangreiche Logsammlungen sollte eine serverseitige Speicherung mit zufälliger Referenz-ID ergänzt werden.

## Konfiguration

Die fachliche Erkennung wird ausschließlich über `data.json` gepflegt.

Wichtige Bereiche:

```json
{
  "record_containers": [],
  "severity_levels": {},
  "field_aliases": {},
  "event_catalog": {},
  "product_catalog": {},
  "rules": []
}
```

### Feldalias ergänzen

```json
"source_ip": {
  "type": "string",
  "aliases": [
    "sourceip",
    "source_ip",
    "srcip",
    "clientip"
  ]
}
```

### Ereignis ergänzen

```json
"example_event": {
  "title": "Beispielereignis",
  "summary": "Ein Beispielereignis wurde erkannt.",
  "category": "general",
  "when": {
    "any_text": [
      "ExampleOperation"
    ]
  }
}
```

### Risikoregel ergänzen

```json
{
  "id": "example_rule",
  "title": "Beispieltreffer",
  "description": "Die Beispielbedingung wurde erkannt.",
  "score": 20,
  "category": "general",
  "when": {
    "event": "example_event"
  }
}
```

## Sicherheit und Datenschutz

- Logdaten werden nicht serverseitig gespeichert.
- Ausgaben werden vor der HTML-Darstellung maskiert.
- Eingaben sind auf 25 MiB begrenzt.
- Geteilte URLs enthalten die komprimierte Investigation und müssen deshalb wie Logdaten behandelt werden.
- Vertrauliche URLs sollten nicht in öffentliche Chats, Tickets, Browser-Synchronisierung oder öffentliche Repositories übernommen werden.

## Aktualisierung

Bei neuen Connectoren oder Feldnamen wird normalerweise nur `data.json` erweitert. Änderungen an `index.php` sind nur erforderlich, wenn neue Operatoren, Darstellungsbereiche oder ein anderes Zustandsmodell benötigt werden.
