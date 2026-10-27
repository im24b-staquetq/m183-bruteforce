# Funktionszuordnung und Zusammenarbeit

Das konkrete Bewertungsraster liegt diesem Repository nicht bei. Die folgende
Zuordnung ist eine Orientierung und keine Zusage einer Note. Klärt Gewichtung,
Pflichtnachweise und die genaue Auslegung mit der Lehrperson.

| Mögliche Kategorie | Implementierung | Nachweis |
|---|---|---|
| Anfällige Anwendung | `auth.py`, Variante `insecure`; korrektes Hashing ohne Login-Limits | Mono findet Testpasswort; Test für unbegrenzte Versuche |
| Persistente Datenhaltung | `database.py`: SQLite-Konten, Zustände, Profile, Audit | Verbindungstests, CLI, echte Worker mit derselben Datei |
| Sichere Passwortspeicherung | Argon2id, RFC-Profil, Zufallssalz je Hash | Parameter- und Salztest |
| Getrennte Angriffe | `mono.py`, `dictionary.py`, `poly.py`, `parallel.py` | Kandidaten- und Integrationstests, vier CLI-Befehle |
| Verteidigung | `fixed.py`, `progressive.py`, `lockout.py`, `audit.py` | Kontrollierte Zeit, Schwellen-, Sperr- und Alarmtests |
| Parallele Korrektheit | Disjunkte Intervalle, globale Reservierungen, SQLite-Transaktion | Aufteilungstests und echte `spawn`-Worker |
| Reproduzierbare Demonstration | Kleine künstliche Daten, expliziter Reset, Limits | README und Messvorlage |
| CIA und fachliche Erklärung | Ehrliche Zuordnung von Wirkung und Grenzen | README, Fachgesprächsfragen |
| Qualität | Type Hints, kleine Funktionen, parametrisierte Abfragen, Ressourcenfreigabe | pytest, Ruff, Review |
| Zusammenarbeit | Geplante Rollen, gegenseitige Erklärungen und Reviews | Eigene tatsächliche Commits, Review-Notizen und Demo-Protokoll ergänzen |

Die private Notiz und echte Rainbow-Tables sind nicht implementiert. In der
Dokumentation werden deshalb keine entsprechenden Funktionen als erledigt bewertet.

## Vorschlag für das Zweierteam

| Schritt | Person A | Person B | Gemeinsam |
|---|---|---|---|
| Schnittstelle | Benötigte Angriffsergebnisse beschreiben | LoginResult und Zustandsregeln beschreiben | Aufruf vs. Prüfung und Fehlerfälle festlegen |
| Basis | Mono und Runner prüfen | Datenbank und unsicheren Login prüfen | Vertikalen Ablauf vorführen |
| Erweiterung | Dictionary, Poly und Parallel; Angriffstests | Profile, Audit und Transaktionen; Schutztests | Gegenseitiger Review |
| Abschluss | Messungen mit gleichem Arbeitsumfang | Sperr- und Alarmdemo | README, Rollenwechsel, Probe-Fachgespräch |

Das Projekt wurde als Ausgangsbasis erzeugt. Diese Tabelle dokumentiert noch keine
tatsächlich von zwei Personen ausgeführten Beiträge. Tragt nur reale Arbeit ein:

| Datum | Person | Geprüfte/geänderte Dateien | Commit oder Review | Was die andere Person jetzt erklären kann |
|---|---|---|---|---|
| … | … | … | … | … |
