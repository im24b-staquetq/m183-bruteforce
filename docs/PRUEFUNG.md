# Tatsächlich ausgeführte Prüfungen

Prüfdatum: **27. Oktober 2026**. Umgebung: Windows, Python **3.14.7**, lokale `.venv`.
Es wurde ausschliesslich gegen temporäre Testdatenbanken und eigene Datenbanken
unter dem ignorierten Verzeichnis `runtime/` gearbeitet. Der Standardpfad
`runtime/demo.db` bleibt für eure eigene Initialisierung frei.

## Installation und Qualität

Tatsächlich ausgeführt:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir runtime/wheels .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
```

Ergebnisse:

- Dokumentierte Installation erfolgreich; `pip check`: `No broken requirements found.`
- Installierbares Wheel erfolgreich gebaut; mit `zipfile` geprüft, dass
  `bruteforce_demo/data/words.txt` enthalten ist.
- Abschliessender Testlauf: **63 passed in 6.21s**.
- Ruff: **All checks passed!**, **22 files already formatted**.
- CLI-Hilfe ausgeführt. Git-Ignore-Regeln geprüft: Umgebungen, Datenbanken,
  Build-Ausgaben und Python-Caches werden ignoriert.

Die Tests umfassen echte Argon2-Prüfungen, temporäre Datenbanken, kontrollierte Zeit,
konkurrierende Verbindungen, Windows-`spawn`-Worker und einen erneuten CLI-Programmstart.
Beim Paralleltest mit zwölf Aufrufen und Sperrschwelle fünf wurden exakt fünf
Passwörter geprüft und sieben Aufrufe blockiert. Der SIGINT-Test erzeugt das Signal
gezielt im Elternprozess, sammelt Workerergebnisse und prüft die Wiederherstellung
des vorherigen Signalhandlers. Das ersetzt keine manuelle Prüfung jeder Terminalumgebung.

## Ausgeführte CLI-Demos

Die folgenden Werte stammen aus einem echten Lauf mit `--db runtime/verification.db`.
Es sind Einzelbeobachtungen, keine garantierten Laufzeiten. Alle Hashes verwenden
das unveränderte RFC-Profil mit 64 MiB, drei Durchläufen und vier Argon2-Threads.

| Angriff | Variante / Profil | Aufrufe | Geprüft | Blockiert | Sekunden | Ergebnis |
|---|---|---:|---:|---:|---:|---|
| Mono, 4 Stellen | insecure | 8 | 8 | 0 | 0,373 | künstliches Testpasswort gefunden |
| Dictionary, mitgelieferte Wörter | insecure | 8 | 8 | 0 | 0,510 | künstliches Testpasswort gefunden |
| Poly, `ab01`, 2 Stellen | insecure | 4 | 4 | 0 | 0,214 | künstliches Testpasswort gefunden |
| Parallel, `[0,16)`, 2 Worker | insecure | 9 | 9 | 0 | 0,633 | künstliches Testpasswort gefunden |
| Mono, Aufruflimit 30 | protected / standard | 30 | 1 | 29 | 0,074 | Aufruflimit erreicht |
| Parallel, `[0,16)`, 2 Worker | protected / standard | 16 | 1 | 15 | 0,232 | Suchraum an Schnittstelle übergeben |
| Mono, Aufruflimit 30 | protected / logging mit Sperrschwelle 5 | 30 | 5 | 25 | 0,243 | Aufruflimit erreicht |

Vor dem geschützten Parallelversuch wurden die Zustände ausdrücklich zurückgesetzt.
Das anschliessende `configure --profile logging --lock-threshold 5` setzte seinerseits
die geschützten Zustände zurück. Die letzten sieben Audit-Ereignisse dieser Sperrdemo
waren fünf `LOGIN_FAILED`, ein `ALARM` und ein `ACCOUNT_LOCKED`. Passwörter und Hashes
erschienen nicht in der Ereignisanzeige. Wiederholte blockierte Aufrufe erzeugten
keine weiteren Ereignisse. `status` und `reset` sind zusätzlich durch den CLI-Test geprüft.

## Gemessener Parallelvergleich mit gleichem Arbeitsumfang

Die zwei Befehle aus [MESSUNGEN.md](MESSUNGEN.md) wurden einmal ausgeführt,
jeweils nach `reset`, auf dem Konto `poly` mit den Kandidaten `0000` bis `0015`.

| Ablauf | Passwortprüfungen | Blockiert | Sekunden |
|---|---:|---:|---:|
| Mono, Aufruflimit 16 | 16 | 0 | 0,782 |
| Parallel, 2 Worker, `[0,16)` | 16 | 0 | 1,016 |

Der Faktor `0,782 / 1,016` ist etwa **0,770**. In diesem einzelnen Vergleich war
Parallelisierung langsamer. Das passt zur gewählten Serialisierung durch SQLite
und zum zusätzlichen Prozessstart; die Messung isoliert diese Ursachen nicht einzeln.
Für belastbarere eigene Ergebnisse mehrfach wiederholen und alle Bedingungen festhalten.

## Was nicht geprüft oder implementiert wurde

- Keine Ausführung unter Python 3.11–3.13 oder unter Linux/macOS. Der Code zielt auf
  Python 3.11 ab; die Paketmetadaten der festgelegten Abhängigkeiten erlauben 3.11.
- Keine manuelle Ctrl+C-Tastatureingabe in unterschiedlichen Windows-Terminals;
  serieller Abbruch und gezielt erzeugtes SIGINT werden automatisiert geprüft.
- Keine interaktive verdeckte Passworteingabe durch einen Menschen im Prüflauf.
  Die zugrunde liegende Login-Schnittstelle wurde umfassend getestet.
- Kein Langzeit-, Last-, Stromausfall- oder Datenbankkorruptionstest. Keine Messung
  unter absichtlich verstellter Systemuhr und kein Nachweis einer Produktionssicherheit.
- Keine vollständige Enumeration grosser Suchräume; das wäre dem Demozweck entgegen.
- Das Wheel wurde gebaut und sein Wortlisteninhalt geprüft; eine zweite vollständig
  frische Umgebung mit ausschliesslicher Wheel-Installation wurde nicht eingerichtet.
- Keine private Notiz, Sitzungen, Rainbow-Tables, Netzwerkdienste oder externen Angriffe.

Die frühe vertikale Basis wurde vor Ergänzung der Schutzlogik separat ausgeführt:
Datenbank → unsicherer Login → Mono, acht Aufrufe und acht Passwortprüfungen bis
zum künstlichen Testpasswort. Die dabei erzeugte `runtime/basis.db` gehört zum frühen
Schema und soll nicht für die fertige Demo verwendet werden. Verwendet `init` mit
dem noch freien Standardpfad oder einem neuen Dateinamen. Es gibt keine automatische
Migration oder stillschweigende Löschung vorhandener Datenbanken.

## Ergänzung: Terminalanzeige am 28. Oktober 2026

- `attack ... --live` ergänzt eine Tabelle mit künstlichem Testkandidaten, Status,
  Aufrufen, Passwortprüfungen und blockierten Aufrufen. Ohne die Option bleibt die
  bisherige Ausgabe erhalten. Audit-Logs enthalten weiterhin keine Passwortkandidaten.
- Vollständiger Testlauf nach der Erweiterung: **71 passed in 8.19s**.
  Die zusätzlichen Tests prüfen alle vier Angriffe mit Live-Anzeige, Sperrfeedback,
  die Ausgabe ohne `--live` und korrekte Fortschrittszähler mit echten Workerprozessen.
- Ruff: **All checks passed!**, **23 files already formatted**.
- CLI-Ausgabe mit einer separaten Demo-Datenbank ausgeführt: Mono ohne Schutz
  zeigte acht Prüfungen bis zum Fund; Parallel mit Sperrschwelle fünf und Aufruflimit
  acht zeigte fünf Prüfungen und drei blockierte Aufrufe inklusive Restwartezeit.
- Es wurde keine künstliche Verzögerung eingebaut. Live-Ausgaben verursachen
  zusätzlichen Ausgabeaufwand; Laufzeitvergleiche deshalb ohne `--live` durchführen.

## Ergänzung: wichtigste BZZ-Anpassungen am 28. Oktober 2026

- Anwendungsklassen besitzen jetzt dokumentierte Properties mit internen Attributen;
  die Zähler werden über `record` und `merge` geändert. Die Profilkonfiguration wird
  mit denselben JSON-Schlüsseln wie zuvor gespeichert.
- Klassen und Funktionen im Anwendungscode sind dokumentiert. Ein gemeinsamer
  Transaktions-Kontext ersetzt die von Pylint beanstandete kombinierte with-Schreibweise.
- Vollständiger Testlauf: **71 passed in 15.15s**, einschliesslich echter Windows-Worker.
- Ruff-Linting und die zusätzliche Prüfung auf fehlende Klassen-/Funktionsdocstrings
  im Anwendungscode sind fehlerfrei.
- Gezielter Pylint-Lauf mit `--persistent=n bruteforce_demo tests`: **9.40/10**.
  Es bleiben unter anderem fehlende Beschreibungen einzelner Tests und Hinweise auf
  umfangreiche Funktionen. Die Punktzahl ist keine Bestätigung vollständiger BZZ-Konformität.

### Restliche Docstrings ergänzt

Die drei Testmodule, alle Testfunktionen und ihre verschachtelten Hilfsfunktionen
sind nun ebenfalls dokumentiert. Ruff und Pylint melden für Anwendung und Tests keine
fehlenden Docstrings mehr. Der vollständige gezielte Pylint-Lauf ergibt **9.83/10**;
Ruff-Linting und Formatprüfung sind fehlerfrei. Ein AST-Vergleich mit dem bisherigen
Stand bestätigt, dass nur Docstrings und Formatierung der drei Testdateien geändert
wurden. Laufzeittests wurden für diese reine Dokumentationsänderung nicht erneut ausgeführt.
