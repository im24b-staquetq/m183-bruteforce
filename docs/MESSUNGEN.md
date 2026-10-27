# Eigene Messungen

Diese Vorlage enthält bewusst keine erfundenen Messwerte. Ein bereits ausgeführter
Prüflauf ist separat in [PRUEFUNG.md](PRUEFUNG.md) gekennzeichnet.
Übernehmt für eure Vorführung die tatsächlichen Zusammenfassungen.

## Rahmenbedingungen

- Datum, Betriebssystem und Python-Version: …
- Rechner/CPU und verfügbarer Arbeitsspeicher: …
- Commit/Stand: …
- Argon2id: 64 MiB, drei Durchläufe, vier Threads (unverändert)
- Datenbankdatei und Profilparameter: …
- Hintergrundlast, Anzahl Wiederholungen und Reset-Verfahren: …

| Angriff | Variante/Profil | Suchraum/Limit | Worker | Login-Aufrufe | Passwortprüfungen | Blockiert | Sekunden | Ergebnis |
|---|---|---|---|---|---|---|---|---|
| Mono | insecure | … | 1 | … | … | … | … | … |
| Dictionary | insecure | … | 1 | … | … | … | … | … |
| Poly | insecure | … | 1 | … | … | … | … | … |
| Parallel | insecure | … | … | … | … | … | … | … |
| Mono | protected / standard | … | 1 | … | … | … | … | … |
| Mono | protected / fixed | … | 1 | … | … | … | … | … |
| Mono | protected / progressive | … | 1 | … | … | … | … | … |
| Mono | protected / lockout | … | 1 | … | … | … | … | … |
| Mono | protected / logging | … | 1 | … | … | … | … | … |

## Fairer Vergleich: seriell und parallel

Ein früher Treffer führt je nach Workerreihenfolge zu verschieden viel Arbeit.
Deshalb hier derselbe kleine vollständige Suchraum ohne passenden Kandidaten:
Das Konto `poly` hat das künstliche Testpasswort `a1`, der Suchraum besteht dagegen
aus den vierstelligen Zahlen `0000` bis `0015`.

```powershell
.\.venv\Scripts\python.exe -m bruteforce_demo reset
.\.venv\Scripts\python.exe -m bruteforce_demo attack mono --variant insecure --username poly --min-length 4 --max-length 4 --max-calls 16 --max-seconds 30
.\.venv\Scripts\python.exe -m bruteforce_demo reset
.\.venv\Scripts\python.exe -m bruteforce_demo attack parallel --variant insecure --username poly --length 4 --start 0 --stop 16 --workers 2 --max-calls 16 --max-seconds 30
```

Beide Läufe müssen 16 Passwortprüfungen und 0 blockierte Aufrufe melden, sofern
das Zeitlimit nicht vorzeitig greift. Nur dann wurde gleich viel geprüft.
Das serielle Ergebnis lautet wegen des exakten Limits „Aufruflimit erreicht“;
das sagt nichts über den Schutz aus. Startkosten sind im Parallelwert enthalten.
Der Reset belässt Audit-Ereignisse und Profil; jeder Lauf beginnt aber ohne Fehlerzustand.

Mindestens dreimal wiederholen, bei Bedarf die Reihenfolge wechseln. Alle Einzelwerte
aufbewahren. Beispielsweise Median statt einer auffällig günstigen Einzelmessung
berichten. Eine Laufzeit unterhalb einer Sekunde kann deutlich schwanken.

`Faktor = serielle Laufzeit / parallele Laufzeit`. Erst wenn bei gleichem Arbeitsumfang
der Wert über 1 liegt, war dieser Parallelversuch schneller. Eine allgemeine
Beschleunigung lässt sich daraus nicht ableiten. In dieser Implementierung ist wegen
der absichtlich umfassenden SQLite-Schreibtransaktion keine parallele Hashprüfung
möglich. Mehr Worker verursachen Start- und Koordinationsaufwand.

## Interpretation für Schutzprofile

Eine kurze geschützte Laufzeit kann gerade bedeuten, dass fast alle Aufrufe billig
abgewiesen wurden. „Schneller fertig“ bedeutet deshalb nicht „leichter geknackt“.
Vergleicht geprüfte Passwörter, blockierte Aufrufe und Ergebnis gemeinsam.
Beim Standardprofil hängt die genaue Zahl der zulässigen Prüfungen vom zeitlichen
Ablauf ab. Für die reine Zählerschwelle das Profil `lockout` ohne Wartezeit verwenden.
Für Alarmereignisse `logging --lock-threshold 5` wie in der README einsetzen.
