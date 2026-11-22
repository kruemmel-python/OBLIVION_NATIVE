# OBLIVION Native – Implementierungsstatus

Aktueller Entwicklungsstand auf Basis von `OBLIVION_NATIVE` (C++20 / Win32 / CMake / WiX MSI).

## Implementiert

- [x] C++20/Win32-Kern ohne Python/Webserver/Framework-Runtime
- [x] Natives GUI-Kontrollzentrum (`Oblivion.exe` / `--gui`) für alle Benutzerfunktionen (Drag & Drop, Analyse, Löschen, Papierkorb, Freispeicher, Zertifikat-Export, Diagnose, Kontextmenü, Optionen)
- [x] Windows Dark/Light Mode & Taskleisten-Fortschritt (`ITaskbarList3`)
- [x] CLI (`OblivionCLI.exe`) inkl. `--json`-Ausgabe
- [x] Direkte statische Top-Level-Shell-Verbs (`OblivionErase`, `OblivionAnalyze`, `OblivionSettings`) für Dateien & Ordner (kompatibel mit Standard-Explorer und Third-Party-Shells wie Nilesoft Shell)
- [x] Laufwerks-Kontextmenü (*„Freien Speicherplatz mit Oblivion überschreiben“*) & Papierkorb-Kontextmenü (*„Papierkorb mit Oblivion sicher leeren“*)
- [x] Mehrfachauswahl über nativen In-Memory-Batch-Broker
- [x] Analyse/Dry-Run
- [x] feste Analyse- und ADS-Ressourcenobergrenzen
- [x] Gesamtfortschritt, Pass, Durchsatz, ETA, Abbruch
- [x] ADS-Erkennung und -Überschreibung
- [x] erneuter ADS-Mengen-/Größenvergleich vor dem Hauptdatenstrom
- [x] Hardlink-Erkennung und drei Strategien
- [x] Schutzpfadprüfung der Hardlink-Namensmenge vor Shared-Overwrite
- [x] Reparse/Junction/Symlink ohne Traversierung
- [x] Blockade von Zielen unter Reparse-Vorfahren
- [x] erweiterte Windows-/Boot-/Profil-Schutzpfade (inkl. dedizierter Freigabe nur für Papierkorb-Inhalte unter `$Recycle.Bin\<SID>\...` ohne `desktop.ini`)
- [x] Sparse/Compressed/EFS-Hinweise
- [x] HDD/SSD/NVMe/TRIM/Dateisystem/Geräteinformationen
- [x] USN-/Shadow-Copy-Hinweise
- [x] Lock-Owner-Diagnose über Windows Restart Manager
- [x] UAC-Retry nur bei Bedarf
- [x] persistente HKCU-Einstellungen
- [x] sichere Metadaten-Umbenennung
- [x] FAST / STANDARD / STRONG sowie Compliance-Presets (`DoD 5220.22-M`, `NIST SP 800-88`, `BSI IT-Grundschutz`, `Gutmann`)
- [x] Freien Speicherplatz sicher überschreiben (`--wipe-free-space`) & Papierkorb sicher leeren (`--empty-recycle-bin`)
- [x] HTML-Löschzertifikat-Export (`--export-certificate`)
- [x] WiX-MSI-Installer (`BUILD_MSI.bat` -> `dist\OblivionSetup-2.1.2.msi`) inkl. Startmenü-Verknüpfung
- [x] Zero-Readback und SHA-256-Readback des finalen Random-Passes
- [x] isolierter, vor Freigabe sicher bereinigter Arbeitspuffer
- [x] bestmöglicher `VirtualLock` des Arbeitspuffers gegen Paging
- [x] harter Fehler bei RNG-, Pufferreservierungs- oder Flush-Fehlern
- [x] Fail-closed-Schutzpfadprüfung direkt in `erase_engine::erase`
- [x] Schutz des eigenen Audit-/Anwendungszustands unter `%LOCALAPPDATA%\Oblivion`
- [x] absolute IPC-Nachrichtendeadline gegen partielle Slow-Clients
- [x] Engine-Grenzprüfung für Enums, Rename-Runden und Puffergrößen
- [x] native Prozesshärtung und read-only `--diagnostics`
- [x] strikte Handle-Prüfung und Microsoft-Signaturpflicht für nachgeladene DLLs
- [x] RAII-Handle-Besitz im kritischen Datei-Löschpfad
- [x] CFG, SDL-Prüfungen, ASLR, DEP/NX und High-Entropy-ASLR
- [x] nativer Engine-Selbsttest für Hardlinks, ADS, Reparse Points, Locks und
      sichere Speicherbereinigung, Engine-Grenzschutz und Prozesshärtung
- [x] Audit 3 mit pseudonymisierten Feldern, DPAPI-HMAC-Schlüssel,
      linearer Integritätskette und SHA-256-Sidecar
- [x] separate Device-Sanitize-Sicherheitsdomäne
- [x] Systemdisk-/Mountpoint-/Volume-Lock-Schutz
- [x] Device-Sanitize-Audit
- [x] native C++-Selbsttests via CTest (`tests/*.ps1` nur optionale manuelle Testbaum-Hilfsskripte)

## MSVC-Compile-Fix 2.0.1

Der erste reale VS2022-Build hat drei Compilerprobleme offengelegt (COM-Export-Bindung, unzulässiger `auto`-Member und `DWORD`/`unsigned` bei `std::min`). Diese Stellen sind in 2.0.1 korrigiert.

## Verifiziert

Version 2.1.1 wurde auf dem Windows-Zielrechner mit Visual Studio 2022 x64,
Windows SDK und `/W4 /WX /permissive- /EHsc /utf-8` gebaut. Für 2.1.2 stehen
der vollständige MSVC-Release-Build, CTest, MSI-Build und die gezielten
Laufzeitprüfungen nach Abschluss der statischen Sicherheitsprüfung noch aus.

```powershell
.\BUILD_WINDOWS.bat
```

Anschließend werden die nativen C++-Tests über CTest ausgeführt; externe PowerShell-Testskripte sind nicht erforderlich.
