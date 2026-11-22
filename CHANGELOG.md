# Changelog

## 2.1.4 – Modernes Windows-11-Kontextmenü & Shell-Kompatibilität

- Der Installer liefert die vorhandene `IExplorerCommand`-Erweiterung samt
  Sparse-Paketmanifest und Assets aus und registriert sie für das moderne
  Windows-11-Kontextmenü.
- Die Paketregistrierung erkennt veraltete oder auf einen anderen Buildpfad
  verweisende Registrierungen und verifiziert den Endzustand.
- Als klassischer Explorer-Fallback (inkl. Third-Party-Shells wie Nilesoft
  Shell) werden wieder direkte statische Top-Level-Verbs (`OblivionErase`,
  `OblivionAnalyze`, `OblivionSettings`) registriert.
- Beim Entfernen des Kontextmenüs über UI/CLI (`--uninstall-shell`) werden
  systemweite MSI-Einträge (`HKLM`) bei Bedarf automatisch per UAC-Abfrage
  (`--uninstall-shell-quiet`) mitbereinigt.

## 2.1.3 – Explorer-Untermenü und Installationsbereinigung

- Die portable UI-Integration und der MSI registrieren Datei- und
  Ordneraktionen wieder gemeinsam im statischen Untermenü **Oblivion** statt
  als drei direkte Explorer-Einträge.
- Der MSI entfernt beim Upgrade die direkten 2.1.2-Verben, bevor das neue
  Untermenü angelegt wird.
- Beim Entfernen über die UI wird jetzt ausdrücklich gemeldet, wenn
  systemweite, vom MSI verwaltete Einträge bestehen bleiben.

## 2.1.2 – Security Hardening

- Dateilöschung, Reparse-Entfernung und Metadaten-Rename sind an das geöffnete
  Handle gebunden; bereits vor dem Öffnen des Ziels bleiben sämtliche
  Vorfahren und danach jede Ebene rekursiver Zielbäume gegen
  Austausch/Junction-Races gesperrt. Hardlinks werden unmittelbar vor dem
  Hauptdatenstrom erneut geprüft; die gefährliche Shared-Content-Strategie
  verlangt unabhängig vom Analysezeitpunkt immer die `HARDLINK`-Bestätigung.
- Schutzpfade stammen aus Windows Known Folders statt manipulierbaren
  Umgebungsvariablen; kanonische Pfade blockieren Kurznamens- und
  Reparse-Aliase. Der eigene Zustand unter `%LOCALAPPDATA%\Oblivion` ist als
  kritischer Schutzpfad gesperrt. Unterhalb der Windows-Profilwurzel sind nur
  Unterpfade des aktuellen Benutzerprofils zulässig; fremde und öffentliche
  Profilbäume bleiben auch unterhalb ihrer Wurzel gesperrt.
- Papierkorbverarbeitung ist vollständig fail-closed, prüft API und Endzustand,
  bindet beide Scans an Volume-GUIDs und verwendet nach der eigenen sicheren
  Entfernung keine destruktive Shell-Leerung mehr. Dadurch kann ein nach dem
  Kontrollscan neu eingestelltes Objekt nicht unüberschrieben von
  `SHEmptyRecycleBinW()` mitgelöscht werden; die Endzustandsabfrage erfolgt
  separat für jedes vollständig erfasste Volume.
- Papierkorb- und ADS-Aufzählung besitzen feste Ressourcenobergrenzen;
  Teilzähler, Diagnosewerte und der erste Win32-Fehler bleiben auch bei
  Abbruch erhalten und werden überlaufsicher aggregiert.
- Analysebäume und ADS pro Datei besitzen feste Obergrenzen. Die ADS-Menge
  wird nach ihrer Verarbeitung unmittelbar vor dem Hauptdatenstrom erneut
  vollständig anhand von Namen und Größen verglichen; Änderungen brechen die
  Operation vor Hauptstrom und Löschen ab.
- Device Sanitize bricht bei unvollständiger Volume- oder
  Systemdisk-Ermittlung ab. Das nach der Bestätigung geöffnete physische Gerät
  wird anhand Größe, Bus, Modell und Seriennummer erneut gegen die bestätigte
  Identität geprüft; Mount- und Systemdisk-Zustand werden unmittelbar vor dem
  Volume-Lock erneut fail-closed ermittelt. Nach einem erfolgreichen
  `FSCTL_LOCK_VOLUME` werden keine neuen Handles auf die gesperrten Volumes
  geöffnet; die abschließende Geräteidentität wird am exklusiven physischen
  Handle geprüft.
- Audit-Schlüssel, Kettenkopf und Datensätze werden bei beschädigtem Zustand
  nicht still ersetzt; Audit- und Zertifikatsdateien werden exklusiv neu
  angelegt, Flush-Fehler sind fatal und Reparse-Komponenten im Auditpfad werden
  abgewiesen. Prüfgrößen und Kettenlänge sind begrenzt. Zertifikate berechnen
  den SHA-256-Wert aus der gesperrten Eingabedatei, escapen alle Auditwerte und
  trennen Integritätsstatus, Vorgangserfolg und tatsächliche Ergebniszähler.
- BCrypt-Hash-Handles werden vor ihrem vom Aufrufer bereitgestellten
  Objektspeicher zerstört. Die atomare Aktualisierung von `chain.head` verwendet
  einen erweiterten absoluten Windows-Pfad und verifiziert den Zielordner als
  reparse-freies Verzeichnis; Regressionstests decken Wiederholungsupdates und
  beschädigte DPAPI-Schlüssel reproduzierbar ab.
- Der MSI bindet die benutzerspezifischen Startmenüeinträge an einen passenden
  HKCU-KeyPath; dadurch stimmen Ressourcen- und KeyPath-Kontext auch für die
  Windows-Installer-ICE-Prüfung überein.
- Zertifikatexporte sperren zusätzlich den vollständigen, reparse-freien
  Eingabevorfahrenbaum und verwenden für HMAC, Kettenprüfung, SHA-256 und
  Parser denselben absoluten Pfad; ein Verzeichnisaustausch kann dadurch keine
  unversiegelten Werte in einen zuvor validierten Bericht einschleusen.
- Audit-Kettenoperationen werden über eine exklusive Lockdatei auch zwischen
  parallelen Windows-Sitzungen serialisiert; Datensatz und SHA-Sidecar bleiben
  bis zur erfolgreichen Versiegelung handlegebunden geöffnet. Unversiegelte
  Audit-, Sidecar-, HMAC- und temporäre Kettenkopfdateien werden auf jedem
  Fehler- und Ausnahmepfad wieder entfernt.
- Shell-Batch-IPC authentisiert EXE-Pfad, Benutzer-SID und Sitzung. Temporäre
  Shell- und Freispeicherpfade verwenden CSPRNG-Namen und folgen keinen
  Reparse-Verzeichnissen; Freispeicher-Chunks werden exklusiv erstellt und bei
  gesperrtem Elternverzeichnis handlegebunden bereinigt. Shell-Deployments
  halten den vollständigen Verzeichnisbaum gesperrt und entfernen alte
  Artefakte ausschließlich über zuvor geprüfte Handles. Lesen und Schreiben
  des Brokers verwenden eine gemeinsame absolute Nachrichtendeadline, sodass
  partielle Slow-Client-Übertragungen das Zeitlimit nicht neu starten.
- Die Freispeicherbereinigung arbeitet nach der Auswahl über den stabilen
  Volume-GUID-Pfad, meldet Fehler der expliziten Artefaktbereinigung und lässt
  auch auf RNG-, Schreib-, Flush- und Abbruchpfaden keine offenen Chunk-Handles
  zurück.
- Umgeleitete Windows-Profilwurzeln werden über `FOLDERID_UserProfiles`
  geschützt; IPC-Ablehnungen beenden keinen legitimen Shell-Batch vorzeitig,
  und modale Fortschritts-/Bestätigungsfenster sperren ihr Besitzerfenster.
- Administrative GPOs für Löschprofil, Verifikation und Shared-Hardlink-Sperre
  werden tatsächlich erzwungen; die optionale Sparse-Paketierung enthält nun
  alle referenzierten PNG-Assets und liefert verlässliche Fehlercodes.
- Destruktive CLI-Automation erfordert explizite Bestätigungstoken; `--json`
  umgeht keine Sicherheitsabfrage mehr; auch nichtdestruktive Spezialbefehle
  weisen unbekannte oder doppelte Argumente zurück.
- UAC-Wiederholungen enthalten exakt die fehlgeschlagenen Ziele und bewahren
  Modus, Verifikation, ADS-, Rename- und Hardlink-Optionen. GUI-Callbacks,
  Datenträger-/WMI-Inspektion und kryptografische Hash-Hilfen geben ihre
  Windows-Ressourcen auch auf C++-Ausnahmepfaden deterministisch frei.
- Automatische UAC-Wiederholungen werden nur aus einer kanonischen,
  reparse-freien Installation unter `Program Files` gestartet. EXE und
  Verzeichnisbaum bleiben während `ShellExecuteExW("runas")` gegen Austausch
  gesperrt; Portable-Builds in benutzerbeschreibbaren Verzeichnissen werden
  nicht automatisch erhöht.
- Ungültige Engine-Enums sowie unbeschränkte Rename-/Pufferoptionen werden vor
  jeder Zieloperation abgewiesen. Auditfehler und fehlgeschlagene erneute
  Zielanalysen stoppen Mehrzielvorgänge fail-closed. GUI-Drops und
  Shell-Auswahlmengen sind begrenzt; Worker benachrichtigen den stabilen
  UI-Thread statt eines möglicherweise wiederverwendeten Fenster-Handles.
- Fortschrittsnachrichten werden auf höchstens eine ausstehende UI-Nachricht
  koalesziert. Ein atomarer Timer-Fallback erkennt den Worker-Abschluss auch
  dann, wenn die abschließende Thread-Nachricht wegen einer erschöpften
  Windows-Message-Queue nicht zugestellt werden konnte.
- Verschachtelte Fortschritts-, Bestätigungs- und Einstellungsdialoge zerstören
  ihre Fenster vor der Freigabe stackgebundener Zustände und reichen ein
  externes `WM_QUIT` anschließend an die Hauptnachrichtenschleife weiter.
- Ausnahmen aus Fortschritts- oder Abbruch-Callbacks werden fail-closed als
  Abbruch behandelt. Bereits abgeschlossene Teiloperationen und Zähler bleiben
  dabei ebenso erhalten wie Teilergebnisse von Papierkorb- und
  Freispeicheroperationen auf internen Ausnahmepfaden.
- Neue Regressionen decken CSPRNG-/Flush-/Papierkorb-/Auditfehler,
  manipulierte Zertifikatwerte und Kettenköpfe, exklusive Audit-/Zertifikat-
  Neuerstellung, Schutzpfad-Aliase, ungültige Engine-Optionen, unvollständige
  Voranalysen, Ressourcenlimits, Callback-Ausnahmen und IPC-Slow-Clients ab.
- Manuelle Testbaum-Hilfen verwenden neue GUID-Verzeichnisse statt rekursiver
  Löschung fester `%TEMP%`-Pfade.
- Das SHA-256-Quellmanifest wird aus getrackten und zulässigen neuen
  Git-Dateien gebildet und erfasst dadurch auch versteckte Konfiguration wie
  `.gitignore`.

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
  - **Papierkorb-Endzustand (`src/recycle_bin.cpp`)**: Fehler bei Aufzählung, `exists`, der Windows-API und der abschließenden `SHQueryRecycleBinW()`-Verifikation werden fail-closed behandelt; Erfolg wird nur bei bestätigtem leerem Endzustand gemeldet.
  - **Freispeicher-Bereinigung (`src/wipe_free_space.cpp`)**: Rückgabewerte von `try_fill_secure_random()` und `FlushFileBuffers()` werden konsequent fail-closed geprüft.
  - **Audit-Kettenprüfung (`src/audit_integrity.cpp`, `src/cli_main.cpp`)**: Neues `verify_audit_chain()` prüft zusätzlich zu `verify_audit_file()` die lückenlose Kette aller `.hmac`-Sidecars bis `chain.head`.
  - **Audit- und Zertifikatseingaben (`src/audit_integrity.cpp`, `src/certificate.cpp`)**: Größenlimits und HTML-Escaping schützen die Prüf- und Exportpfade vor Ressourcenerschöpfung und eingebettetem aktivem HTML.
  - **Zertifikate (`src/certificate.cpp`)**: Wortlaut auf *„Technischer Datenvernichtungs- und Auditbericht“* präzisiert und Einzel-HMAC vs. vollständige Kettenprüfung getrennt ausgewiesen.
  - **Device Sanitize (`src/device_main.cpp`)**: Audit unterscheidet klar zwischen angenommenem Windows-Storage-Stack-IOCTL (`ApiRequestAccepted`, `CompletionScope`) und fehlender unabhängiger physischer Controller-Verifikation (`IndependentPhysicalVerification: not_performed`).
  - **Regressionstests**: CSPRNG- und Flush-Fehler, unvollständige Papierkorb-Aufzählungen, API-/Endzustandsfehler sowie manipulierte Audit-Ketten und Zertifikatseingaben sind automatisiert abgedeckt.
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
