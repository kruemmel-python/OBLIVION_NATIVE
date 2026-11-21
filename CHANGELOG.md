# Changelog

## 2.1.1 – GUI-Kontrollzentrum & Kontextmenü-Kompatibilität

- **Natives GUI-Kontrollzentrum (`Oblivion.exe` / `--gui`)**:
  - Vollständige Desktop-Oberfläche (`src/main_window.cpp`) im Windows Dark/Light Mode mit Drag & Drop, Datei-/Ordner-Auswahl, Dry-Run-Analyse, sicherem Löschen, Papierkorb-Leerung, Laufwerksauswahl für Freispeicher-Bereinigung, Einstellungsprofil-Anzeige, HTML-Zertifikat-Export, Systemdiagnose und Kontextmenü-Verwaltung.
  - Neue Startmenü-Verknüpfung *„Oblivion Native“* im WiX-MSI-Installer (`installer/Oblivion.wxs`).
- **Explorer-Kontextmenü (Nilesoft-Shell- & Standard-Explorer-kompatibel)**:
  - Umstellung von `SubCommands=""`-Untermenüs auf direkte Top-Level-Verbs (`OblivionErase`, `OblivionAnalyze`, `OblivionSettings`) unter `*\shell` und `Directory\shell` in `src/shell_integration.cpp` und `installer/Oblivion.wxs`.
  - Neuer Laufwerks-Eintrag `Drive\shell\OblivionWipeFree` (*„Freien Speicherplatz mit Oblivion überschreiben“*).
  - `(Default)`-Wert für `OblivionEmpty` auf dem Windows-Papierkorb ergänzt.
- **Papierkorb-Löschpfad-Fix**:
  - `path_validator` erlaubt über `allow_recycle_bin_items` ausschließlich Einträge innerhalb von `$Recycle.Bin\<SID>\<Objekt>` (Tiefe ≥ 3, ohne `desktop.ini`), während `$Recycle.Bin` selbst und `<SID>`-Ordner weiter blockiert bleiben.
  - Doppelter Case-Insensitive-Scan (`$Recycle.Bin` + `$RECYCLE.BIN`) in `src/recycle_bin.cpp` behoben.

- **Sicherheits- & Integritäts-Fixes (2.1.1)**:
  - **Papierkorb (`src/recycle_bin.cpp`)**: `SHEmptyRecycleBinW()` wird nur noch ausgeführt, wenn alle Papierkorb-Objekte ohne Fehler und ohne Abbruch sicher überschrieben wurden.
  - **Freispeicher-Bereinigung (`src/wipe_free_space.cpp`)**: Rückgabewerte von `try_fill_secure_random()` und `FlushFileBuffers()` werden konsequent fail-closed geprüft.
  - **Audit-Kettenprüfung (`src/audit_integrity.cpp`, `src/cli_main.cpp`)**: Neues `verify_audit_chain()` prüft zusätzlich zu `verify_audit_file()` die lückenlose Kette aller `.hmac`-Sidecars bis `chain.head`.
  - **Zertifikate (`src/certificate.cpp`)**: Wortlaut auf *„Technischer Datenvernichtungs- und Auditbericht“* präzisiert und Einzel-HMAC vs. vollständige Kettenprüfung getrennt ausgewiesen.
  - **Device Sanitize (`src/device_main.cpp`)**: Audit unterscheidet klar zwischen angenommenem Windows-Storage-Stack-IOCTL (`ApiRequestAccepted`, `CompletionScope`) und fehlender unabhängiger physischer Controller-Verifikation (`IndependentPhysicalVerification: not_performed`).
  - **Versionierung & Test-Doku**: Einheitlich auf Version `2.1.1` (`CMakeLists.txt`, `Oblivion.wxs`, `BUILD_MSI.bat`, `BUILD_WINDOWS.bat`, `AppxManifest.xml`) umgestellt; `tests/README.md` präzisiert die Rolle der optionalen `.ps1`-Hilfsskripte.

## 2.1.0 – Enterprise & Modern Windows Features

- **Erweiterte Löschstandards / Compliance-Presets**:
  - `DoD 5220.22-M`: 3-Pass-Muster (Nullen + Einsen + Kryptografischer Zufall mit Verifikation)
  - `NIST SP 800-88 Rev. 1 Clear`: 1-Pass-Nullüberschreibung mit vollständigem Readback
  - `BSI IT-Grundschutz`: 3-Pass-Standard nach Vorgaben des BSI
  - `Gutmann (35 Passes)`: Vollständiger 35-Pass-Algorithmus nach Peter Gutmann für magnetische Altdatenträger
- **Freien Speicherplatz sicher überschreiben ("Wipe Free Space")**:
  - Sichere Überschreibung von ungenutztem Speicherplatz auf Volumes via Chunk-Dateien bis zur Vollauslastung ohne Beeinträchtigung vorhandener Daten.
- **Papierkorb-Integration**:
  - Direkte Menüoption auf dem Windows-Papierkorb: *„Papierkorb mit Oblivion sicher leeren“*.
  - Kryptografische Vernichtung aller im Papierkorb befindlichen Objekte auf allen Laufwerken (`$Recycle.Bin`).
- **Dark Mode & Taskleisten-Integration**:
  - Nativer Windows 11/10 Dunkelmodus (`DWMWA_USE_IMMERSIVE_DARK_MODE` & Explorer Dark Theme) für Fortschritts- und Einstellungsdialoge.
  - Live-Fortschrittsanzeige in der Windows-Taskleiste via `ITaskbarList3` (Grün = Fortschritt, Gelb = Pausiert/Abbruch).
- **Löschzertifikat & Reporting**:
  - Export druckbarer, revisionssicherer Datenvernichtungsberichte als HTML (`--export-certificate`).
  - Visueller Nachweis mit DPAPI-HMAC-Validierungsbadge und SHA-256-Prüfsumme.
- **Automatisierung & Enterprise**:
  - Maschinenlesbare JSON-Ausgabe für alle CLI-Operationen (`--json`).
  - Vorbereitung für modernes Windows 11 Top-Level Kontextmenü via Sparse Package (`packaging/windows11/`).
  - Administrative Gruppenrichtlinien-Vorlagen (`packaging/gpo/Oblivion.admx`, de-DE / en-US).
  - Neuer MSI-Installer mit WiX v7 Toolset (`BUILD_MSI.bat`).

## 2.0.2 – Windows-11 Shell Batch Hotfix

- Explorer-Shellintegration vollständig auf statische Shell-Verbs umgestellt.
- Aktiver Explorer-Pfad lädt keine OBLIVION-COM-DLL mehr.
- Mehrfachauswahl wird in `Oblivion.exe` über einen lokalen In-Memory-Named-Pipe-Batch gebündelt.
- `Analysieren (Dry Run)` und `Sicher löschen` verwenden denselben Batch-Pfad.
- `Optionen` erhält einen Single-Instance-Guard und öffnet bei Mehrfachauswahl nur einmal.
- Analyseansicht gruppiert identische Datenträgerinformationen und listet Ziele separat.
- Fortschrittsfenster erhält explizites Hintergrund-Repaint gegen Ghosting.
- Shell-Smoke-Test prüft jetzt den tatsächlich aktiven Batch-Broker statt der alten COM-DLL.
- Alte PowerShell-Testskripte aus dem Projekt entfernt.

## Unveröffentlicht – Engine-Härtung

- Sicherer, isolierter Schreib- und Readback-Puffer mit garantierter
  Speicherbereinigung vor Freigabe und bestmöglichem Paging-Schutz.
- Kontrollierte Fehlerpfade für CSPRNG- und Pufferreservierungsfehler.
- Fehlgeschlagene `FlushFileBuffers`-Aufrufe sind nun fatal; ein betroffenes
  Ziel wird nicht anschließend gelöscht.
- Nativer Engine-Selbsttest um die sichere Pufferbereinigung erweitert.
- GPU-Entropie, rohe Dateisystem-/Sektorzugriffe und SSD-Vollschreiben bewusst
  nicht übernommen, da sie keine belastbare Löschgarantie liefern oder das
  Risiko für Dateisystem und Datenträger erhöhen.
- Direkte Engine-Aufrufe validieren Schutzpfade jetzt nochmals fail-closed.
- Native Laufzeithärtung gegen DLL-Preloading, Heap-Korruption, dynamischen
  Code, Legacy Extension Points und unsichere Images.
- Neuer read-only Diagnosemodus `--diagnostics` für CLI und Device-Tool.
- Build-Härtung um `/sdl`, Control Flow Guard, ASLR, DEP/NX und
  High-Entropy-ASLR erweitert.
- Prozesshärtung um strikte Handle-Prüfung und Microsoft-Signaturpflicht für
  nachgeladene Binärmodule erweitert.
- Kritische Datei-Handles werden im Engine-Pfad nun über RAII verwaltet.
- Audit 3 anonymisiert sensible Pfade, Gerätekennungen und Diagnosewerte per
  HMAC-SHA-256, schützt den lokalen Schlüssel mit DPAPI und verkettet Datensätze
  über einen persistenten HMAC-Kettenkopf.
- Selbsttests erkennen Audit-Manipulationen und prüfen den DLL-Preloading-Schutz.

## 2.0.1 – MSVC Compile Fix

- COM-Exports der `OblivionShell.dll` auf SDK-konforme `STDAPI`-Definitionen umgestellt.
- Exporte `DllGetClassObject` und `DllCanUnloadNow` über `OblivionShell.def` fest definiert.
- `progress_window.cpp`: `steady_clock::time_point` statt unzulässigem `auto`-Datenmember.
- `settings.cpp`: explizite Typangleichung zwischen `DWORD` und `unsigned` für `/W4 /WX`.
- Keine Funktionalität von 2.0.0 entfernt.

## 2.0.0

- Native Fortschritts-GUI und Abbruch
- Analyse/Dry-Run
- ADS-Verarbeitung
- Hardlink-Erkennung und Schutzstrategien
- Reparse-Vorfahren-Schutz
- erweiterte Schutzpfade
- HDD/SSD/NVMe/TRIM/USN/VSS-Inspektion
- Lock-Owner über Restart Manager
- bedarfsgesteuerter UAC-Retry
- persistente Optionen
- IExplorerCommand-Untermenü mit Mehrfachauswahl
- Audit 2 + SHA-256
- separate Device-Sanitize-Domäne mit Systemdisk-/Mountpoint-/Volume-Lock-Schutz
- Safe-Testskripte
