# OBLIVION native Tests

Für automatisierte CTest-Läufe werden keine PowerShell-Testskripte verwendet.

Die Testziele werden als native C++-Programme zusammen mit dem Projekt gebaut:

- `oblivion_shell_smoke` prüft den In-Memory-Shell-Batch-Broker für Mehrfachauswahl.
- `oblivion_engine_self_test` prüft Engine-Grenzen, Hardlinks, ADS, Reparse Points,
  Locks, Speicherbereinigung, Prozesshärtung sowie die HMAC- und
  Kettenintegrität der Auditdaten einschließlich eines manipulierten
  `chain.head`. Er simuliert außerdem CSPRNG- und Flush-Fehler sowie
  unvollständige, fehlgeschlagene und abgebrochene Papierkorboperationen sowie
  nicht verifizierbare oder nicht leere Papierkorb-Endzustände und eine
  Änderung des Papierkorbs zwischen Aufzählung und Shell-Bereinigung. Der
  Zertifikatsexport wird zudem mit einem manipulierten Auditwert auf korrektes
  HTML-Escaping geprüft.

Die Simulationen werden ausschließlich über `oblivion_core_test` eingebunden.
Die Release-Anwendungen verwenden weiterhin die direkten Windows- und BCrypt-
APIs und enthalten keine Testadapter.

Nach dem Release-Build:

```text
ctest --test-dir build -C Release --output-on-failure
```

Die optionalen PowerShell-Skripte `CREATE_SAFE_TEST_TREE.ps1` und
`VERIFY_AFTER_ERASE.ps1` in diesem Verzeichnis dienen ausschließlich als manuelle
Hilfswerkzeuge zum Anlegen und Prüfen isolierter Testbäume.

Die Tests arbeiten ausschließlich mit temporären Testdaten und umgehen keine
Schutzpfadprüfung der Produktions-Engine.
