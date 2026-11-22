# OBLIVION native Tests

Für automatisierte CTest-Läufe werden keine PowerShell-Testskripte verwendet.

Die Testziele werden als native C++-Programme zusammen mit dem Projekt gebaut:

- `oblivion_shell_smoke` prüft den In-Memory-Shell-Batch-Broker für
  Mehrfachauswahl sowie die absolute Deadline gegen partielle Slow-Clients.
- `oblivion_engine_self_test` prüft Engine-Grenzen, Hardlinks, ADS, Reparse Points
  einschließlich gesperrter Reparse-Vorfahren, Locks, Speicherbereinigung,
  Prozesshärtung sowie die HMAC- und
  Kettenintegrität der Auditdaten einschließlich eines manipulierten
  `chain.head`. Er simuliert außerdem CSPRNG- und Flush-Fehler sowie
  unvollständige, fehlgeschlagene und abgebrochene Papierkorboperationen sowie
  nicht verifizierbare oder nicht leere Papierkorb-Endzustände und eine
  Änderung des Papierkorbs während der Verarbeitung. Eine destruktive
  Shell-Bereinigung wird bewusst nicht verwendet; der Endzustand wird pro
  erfasstem Volume abgefragt. Abbruchtests prüfen zusätzlich, dass Teilzähler,
  Fehler und Lock-Diagnosen nicht verloren gehen. RNG- und Flush-Simulationen
  bestätigen, dass keine Freispeicher-Wipe-Artefakte zurückbleiben. Der
  Zertifikatsexport wird zudem mit einem manipulierten Auditwert auf korrektes
  HTML-Escaping geprüft. Unvollständige Voranalysen müssen die starke
  Texteingabe verlangen; nach Manipulation von `chain.head` darf kein weiterer
  Datensatz als erfolgreich versiegelt werden. Die UAC-Argumenterzeugung wird
  mit allen sicherheitsrelevanten Löschoptionen geprüft. Ungültige Enumwerte,
  überhöhte Rename-Runden und ungültige Puffergrößen müssen vor jeder
  Zieländerung von der Engine abgewiesen werden. Simulierte Ausnahmen aus
  Fortschritts- und Abbruch-Callbacks dürfen nicht aus der Engine entweichen,
  keine weiteren Ziele löschen und bereits abgeschlossene Teilergebnisse nicht
  verwerfen. Ein künstlich niedriges Analyse-Limit prüft den fail-closed
  Abbruch übergroßer Zielbäume. Audit-RNG-Fehler nach Dateierstellung dürfen
  weder unversiegelte Artefakte hinterlassen noch die bestehende Kette ändern.
  Reparse-Vorfahren werden sowohl für Zertifikatseingaben als auch für
  Zertifikatsausgaben abgewiesen.

Die Simulationen werden ausschließlich über `oblivion_core_test` eingebunden.
Die Release-Anwendungen verwenden weiterhin die direkten Windows- und BCrypt-
APIs und enthalten keine Testadapter.

Nach dem Release-Build:

```text
ctest --test-dir build -C Release --output-on-failure
```

Die optionalen PowerShell-Skripte `CREATE_SAFE_TEST_TREE.ps1` und
`VERIFY_AFTER_ERASE.ps1` in diesem Verzeichnis dienen ausschließlich als manuelle
Hilfswerkzeuge zum Anlegen und Prüfen isolierter Testbäume. Der Ersteller
verwendet pro Lauf neue GUID-Pfade und führt keine rekursive Vorab-Löschung
aus; die ausgegebenen Pfade werden dem Verifier explizit übergeben.

Die Tests arbeiten ausschließlich mit temporären Testdaten und umgehen keine
Schutzpfadprüfung der Produktions-Engine.
