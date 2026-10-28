# Brute-Force-Demo – Präsentation

Lokale Login-Demo mit Python, SQLite und Argon2id. Ausschliesslich künstliche Testkonten verwenden.
Alle Befehle in PowerShell im Projektverzeichnis ausführen (Python ab 3.11).

## 1. Installation und Vorbereitung

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\bruteforce-demo.exe init
```

Die ersten beiden Befehle sind nur für die Einrichtung nötig. Falls `py` fehlt, `python` verwenden.
`init` erstellt `runtime/demo.db` und überschreibt keine bestehende Datei.
Bei einer Wiederholung stattdessen `reset` verwenden.

**Künstliche Demo-Testpasswörter:**

| Konto | Testpasswort |
|---|---|
| `pin` | `0007` |
| `dictionary` | `Lernwort1` |
| `poly` | `a1` |

## 2. Unsicher gegen geschützt vergleichen

`--live` zeigt Testkandidaten, Status und Zähler während des Angriffs.
Ohne diese Option erscheint nur die Zusammenfassung. Es gibt keine künstliche Verlangsamung.

```powershell
# Ohne Begrenzung: 0007 wird nach acht Prüfungen gefunden.
.\.venv\Scripts\bruteforce-demo.exe attack mono --variant insecure --live

# Mit Schutz: Schnelle Folgeversuche werden vor der Passwortprüfung blockiert.
.\.venv\Scripts\bruteforce-demo.exe configure --profile standard
.\.venv\Scripts\bruteforce-demo.exe attack mono --variant protected --live
```

Das Standardprofil kombiniert progressive Wartezeit, Sperre nach fünf falschen Prüfungen und Logging.
**Zeigen:** Login-Aufrufe, tatsächlich geprüfte Passwörter und blockierte Versuche unterscheiden.
Die genaue Zahl blockierter Aufrufe hängt vom zeitlichen Ablauf ab.

## 3. Weitere Angriffe zeigen

```powershell
.\.venv\Scripts\bruteforce-demo.exe attack dictionary --username dictionary --variant insecure --live
.\.venv\Scripts\bruteforce-demo.exe attack poly --username poly --variant insecure --live
.\.venv\Scripts\bruteforce-demo.exe attack parallel --username pin --variant insecure --workers 2 --live
```

- **Dictionary:** Künstliche Wortliste mit Grossschreibung und Ziffernvarianten.
- **Poly:** Kleine Demo mit `ab01`, Länge zwei; Kandidaten werden einzeln erzeugt.
- **Parallel:** Zwei Worker teilen `0000` bis `0015` ohne Überschneidungen auf.

Für geschützte Vergleiche `insecure` durch `protected` ersetzen und vorher `reset` ausführen.
Alle Angriffe stoppen bei Erfolg, standardmässig spätestens nach 30 Aufrufen oder etwa zehn Sekunden.
Abbruch mit **Ctrl+C**; bereits laufende Prüfungen können noch fertig werden.

## 4. Sperre und Alarm zeigen

```powershell
.\.venv\Scripts\bruteforce-demo.exe configure --profile logging --lock-threshold 5
.\.venv\Scripts\bruteforce-demo.exe attack mono --variant protected
.\.venv\Scripts\bruteforce-demo.exe events
.\.venv\Scripts\bruteforce-demo.exe status
```

Erwartung bei schnellen Aufrufen: fünf Passwortprüfungen, danach Sperre für zehn Sekunden.
Der dritte Fehlversuch löst einen Alarm aus. Blockierte Aufrufe erzeugen keine weiteren Alarme.
Optional manuell anmelden: `.\.venv\Scripts\bruteforce-demo.exe login pin`.

## 5. Reset, einzelne Schutzprofile und Tests

```powershell
# Für eine neue Vorführung; behält Konten und das gewählte Profil.
.\.venv\Scripts\bruteforce-demo.exe reset --clear-events

# Optional: feste oder progressive Wartezeit einzeln vorführen.
.\.venv\Scripts\bruteforce-demo.exe configure --profile fixed
.\.venv\Scripts\bruteforce-demo.exe attack mono --variant protected
.\.venv\Scripts\bruteforce-demo.exe configure --profile progressive
.\.venv\Scripts\bruteforce-demo.exe attack mono --variant protected
```

`configure` aktiviert jeweils das neue Profil und setzt geschützte Fehlversuchszustände zurück.
`reset` ohne `--clear-events` behält die bisherigen Audit-Ereignisse.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

## Wichtig beim Erklären

- Auch die unsichere Variante speichert gesalzene Argon2id-Hashes und verwendet parametrisierte SQL-Abfragen.
- Schutz wirkt in der Login-Logik; SQLite-Transaktionen halten Zähler über Prozesse und Neustarts konsistent.
- Parallel ist nicht automatisch schneller: Die SQLite-Schreibtransaktion serialisiert hier die Prüfungen.
- CIA: Hashing schützt Vertraulichkeit, Transaktionen schützen Konsistenz; Kontosperren können die Verfügbarkeit beeinträchtigen.
- Die lokale Schnittstelle ist keine Sicherheitsgrenze gegen jemanden mit Dateizugriff.

Details bei Bedarf: [Hintergrund und Fachgespräch](docs/HINTERGRUND.md),
[Messvorlage](docs/MESSUNGEN.md), [Prüfprotokoll](docs/PRUEFUNG.md),
[Bewertung und Arbeitsteilung](docs/BEWERTUNG.md).
