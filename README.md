# OBLIVION Native 2.1.2

Native C++20/Win32-Neuentwicklung des OBLIVION-Löschwerkzeugs mit vollständigem Desktop-Kontrollzentrum, Explorer-Integration, Compliance-Presets, Audit-Zertifikaten und separater Device-Sanitize-Domäne.

## Komponenten

Nach dem Build:

- `Oblivion.exe` – natives Windows-GUI-Kontrollzentrum (ohne Konsolenfenster; über `--gui` oder ohne Parameter) sowie Shell-Batch-Host
- `OblivionCLI.exe` – CLI/Dry-Run/JSON-Ausgabe/erweiterte Optionen
- `OblivionShell.dll` – Kompatibilitätsartefakt für Windows-11-Sparse-Package-Tests; im Standard-Explorer-Pfad werden direkte statische Shell-Verbs genutzt
- `OblivionDevice.exe` – getrennte, stark abgesicherte Device-Sanitize-Domäne

GUI und CLI verwenden dieselbe C++-Engine (`oblivion_core`).

## Implementiert

- **GUI-Kontrollzentrum (`Oblivion.exe`)** mit Drag & Drop, Datei-/Ordner-Auswahl, Dry-Run-Analyse, sicherem Löschen, Papierkorb-Leerung, Laufwerks-Freispeicher-Bereinigung, Einstellungsprofil-Anzeige, HTML-Zertifikat-Export, Systemdiagnose und Kontextmenü-Verwaltung
- **Direkte Explorer-Kontextmenüeinträge** (kompatibel mit Standard-Explorer und Third-Party-Shells wie Nilesoft Shell):
  - Dateien & Ordner (`*` / `Directory`): **Mit Oblivion sicher löschen**, **Mit Oblivion analysieren (Dry Run)**, **Oblivion: Optionen**
  - Laufwerke (`Drive`): **Freien Speicherplatz mit Oblivion überschreiben**
  - Papierkorb (`CLSID\{645FF040-5081-101B-9F08-00AA002F954E}`): **Papierkorb mit Oblivion sicher leeren**
- Mehrfachauswahl über statische Windows-Shell-Verbs + nativen In-Memory-Batch-Broker in `Oblivion.exe`
- Native Fortschritts-GUI & Windows Dark/Light Mode inkl. Taskleisten-Fortschritt (`ITaskbarList3`): aktuelles Objekt, Phase, Pass, Gesamtfortschritt, Durchsatz, ETA, Abbrechen
- Compliance-Presets zusätzlich zu FAST/STANDARD/STRONG: **DoD 5220.22-M**, **NIST SP 800-88**, **BSI IT-Grundschutz** und **Gutmann (35 Passes)**
- **Freien Speicherplatz überschreiben** (`--wipe-free-space`) & **Papierkorb sicher leeren** (`--empty-recycle-bin`)
- **HTML-Löschzertifikat** (`--export-certificate`) aus DPAPI-HMAC-verketteten Audit-Logs
- Dry-Run mit Dateien, Ordnern, Bytes, ADS, Hardlinks, Reparse Points, Sparse, NTFS-Komprimierung, EFS, Read-only, nicht zugreifbaren Einträgen
- HDD/SSD/NVMe, TRIM, Dateisystem, Gerät, Bus, PhysicalDrive, USN-Journal und Shadow-Copy-Hinweise
- Persistente Optionen unter `HKCU\Software\Oblivion`
- Erzwingbare Maschinen-/Benutzer-GPOs für Löschprofil, Readback-Verifikation
  und die Sperre von Shared-Hardlink-Overwrite
- Hardlink-Strategien: blockieren / nur Linknamen löschen / Shared Content nach zusätzlicher Freigabe
- vollständige Schutzpfadprüfung aller ermittelbaren Hardlink-Namen vor Shared-Overwrite
- ADS-Überschreibung vor dem Hauptdatenstrom
- Reparse/Junction/Symlink: niemals traversieren; Ziele unter einem Reparse-Vorfahren werden blockiert
- sichere zufällige Metadaten-Umbenennung
- per `VirtualAlloc` isolierter Löschpuffer, bestmöglicher `VirtualLock` gegen
  Auslagerung und garantiertes `SecureZeroMemory` vor der Speicherfreigabe
- RNG-, Speicher- und Datenträger-Flush-Fehler führen kontrolliert zum Abbruch
  statt zu einem unvollständig gemeldeten Erfolg
- erneute Fail-closed-Schutzpfadprüfung direkt an der öffentlichen Engine-Grenze
- Prozesshärtung: sichere DLL-Suche, Heap-Korruptionsabbruch, gesperrter
  dynamischer Code, strikte Handle-Prüfung, gesperrte Legacy Extension Points,
  unsichere Images und nicht von Microsoft signierte nachgeladene DLLs
- Windows Restart Manager für Lock-Owner-Diagnose
- UAC-Neustart nur nach `ERROR_ACCESS_DENIED` und ausschließlich aus einer
  gegen Binary-Planting gesperrten Installation unter `Program Files`
- Audit 3 mit Operation UUID, pseudonymisierten HMAC-Referenzen,
  DPAPI-geschütztem lokalem Schlüssel, linearer HMAC-Kette und
  `.sha256`-Sidecar
- getrenntes Device-Sanitize mit Systemdisk-Hartsperre, Mountpoint-Prüfung, `FSCTL_LOCK_VOLUME`, doppelter exakter Bestätigung, Windows Storage Stack und separatem Device-Audit

## Löschmodi

### FAST

1× kryptographische Zufallsdaten via `BCryptGenRandom`. Standardmäßig ohne Readback.

### STANDARD

1. Random
2. Zero
3. byteweiser Readback des finalen Null-Passes

### STRONG

1. Random
2. Zero
3. Random
4. SHA-256-Readback-Verifikation des finalen Random-Passes

`FlushFileBuffers` wird nach jedem Schreibpass verwendet. Schlägt der Flush
fehl, wird das Ziel nicht gelöscht und der Vorgang als Fehler beendet.

Die Readback-Prüfung bestätigt den logisch zurückgelesenen finalen Pass. Sie
behauptet ausdrücklich keine Sicht auf verborgene SSD-FTL-Kopien. Eine
Shannon-Entropiemessung wäre dafür kein Ersatz: Sie bewertet eine
Byte-Verteilung, nicht die physische Persistenz eines Schreibvorgangs.

## HDD vs. SSD/NVMe

Bei SSD/NVMe meldet OBLIVION ausdrücklich, dass dateibasiertes Überschreiben wegen Flash Translation Layer/Wear-Leveling keine Garantie für jede historische physische Kopie geben kann. Shadow Copies, USN-Historie und externe Backups werden nicht stillschweigend als „mitgelöscht“ behauptet.

## Schutzregeln

Hart gesperrt sind u. a.:

- Laufwerkswurzeln (`C:\` usw.)
- `%SystemRoot%`
- `%ProgramFiles%` / `%ProgramFiles(x86)%`
- `%ProgramData%`
- `C:\Users` und Benutzerprofil-Wurzeln
- `System Volume Information`, `$Recycle.Bin` (im normalen Dateipfad; nur `secure_empty_recycle_bin` darf Objekte unter `$Recycle.Bin\<SID>\...` ohne `desktop.ini` löschen), `Recovery`, `EFI`, `Boot`
- `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`, `bootmgr`, `bootnxt`
- UNC-/Device-Namespace-Ziele im normalen File-Erase-Pfad
- direkte ADS-Zielsyntax
- Ziele, deren **Vorfahren** Reparse Points/Junctions/Symlinks sind

Ein Reparse Point als direkt ausgewähltes Ziel wird nur selbst entfernt; sein Ziel wird nie betreten.

## Hardlinks

Standard: Inhaltsüberschreibung blockieren. Die GUI lässt eine bewusste Auswahl zu. Die gefährliche Shared-Content-Variante benötigt zusätzlich `HARDLINK` als Texteingabe und prüft die bekannte Hardlink-Namensmenge gegen die Schutzpfade. Kann die Namensmenge nicht vollständig ermittelt werden, wird Shared-Overwrite blockiert.

## Große Operationen

Zusätzliche Texteingabe `OBLIVION` ab:

- mehr als 100 Dateien oder
- mindestens 1 GiB logische Daten oder
- mehr als 50 Verzeichnisse
- oder einer unvollständigen Voranalyse

## Nichtinteraktive CLI-Bestätigung

`--json` ist kein Bestätigungs-Bypass. Destruktive JSON-/Automationsaufrufe
benötigen ein explizites Token:

```powershell
.\dist\OblivionCLI.exe --json --confirm-destruction OBLIVION "C:\Test\groß"
.\dist\OblivionCLI.exe --empty-recycle-bin --json --confirm-destruction OBLIVION
.\dist\OblivionCLI.exe --wipe-free-space "D:\" --json --confirm-destruction OBLIVION
```

Für kleine Dateioperationen lautet das von der Analyse erwartete Token `JA`,
für große oder unvollständig analysierte Operationen `OBLIVION`. Die riskante
Shared-Hardlink-Strategie verlangt zusätzlich
`--confirm-hardlink HARDLINK`.

## Einstellungen

Über **Oblivion → Optionen** oder:

```powershell
.\dist\Oblivion.exe --settings
```

können Standardmodus, Verifikation, ADS-Verarbeitung, Rename-Runden und sichere Hardlink-Strategie gespeichert werden. `overwrite_shared_content` wird absichtlich nie persistent als Standard gespeichert.

## Audit

Pfad:

```text
%LOCALAPPDATA%\Oblivion\Audit
```

Audit-Dateiname enthält Zeitstempel + Operation-ID-Fragment. Zielpfade,
Volume-IDs, Geräteseriennummern, Diagnosemeldungen und Prozessnamen werden nicht
im Klartext protokolliert, sondern als HMAC-SHA-256-Referenzen. Der HMAC-Schlüssel
liegt ausschließlich DPAPI-geschützt unter dem Windows-Benutzerkonto vor.

Zusätzlich entstehen `.sha256`- und `.hmac`-Sidecars. Jeder HMAC-Datensatz ist
mit seinem Vorgänger verkettet; `chain.head` hält den aktuellen Kettenkopf. Das
erkennt nachträgliche Inhaltsmanipulationen, ist aber keine externe notarielle
Signatur und kein physikalischer Löschbeweis.

Einzelnen Auditdatensatz prüfen:

```powershell
.\dist\OblivionCLI.exe --verify-audit "C:\Pfad\zum\oblivion_....log"
```

## Device Sanitize

Geräte anzeigen:

```powershell
.\dist\OblivionDevice.exe --list
```

Sanitize ist absichtlich **nicht** Teil des Explorer-Menüs. Voraussetzungen:

- Administratorrechte
- Ziel ist nicht die Windows-Systemdisk
- keine erkannten Laufwerksbuchstaben/Ordner-Mountpoints auf dem Zieldatenträger
- alle zugehörigen Volumes müssen exklusiv mit `FSCTL_LOCK_VOLUME` sperrbar sein
- expliziter Gefahrenschalter
- `--confirm ERASE-PHYSICALDRIVE<N>`
- zweite interaktive Eingabe desselben Tokens

Beispielstruktur – PhysicalDrive-Nummer vorher mit `--list` prüfen:

```text
OblivionDevice.exe --sanitize 3 --method default --confirm ERASE-PHYSICALDRIVE3 --i-understand-this-erases-the-entire-device
```

Block-/Crypto-Sanitize wird im Tool nur für NVMe freigegeben. OBLIVION dismountet Volumes nicht automatisch. Nach einem tatsächlich gestarteten Storage-Stack-Auftrag wird ein separates Device-Sanitize-Audit im normalen Audit-Verzeichnis geschrieben.

## Build

Voraussetzungen: Windows 10/11 x64, Visual Studio 2022, Desktopentwicklung mit C++, Windows SDK, VS-CMake.

```powershell
.\BUILD_WINDOWS.bat
```

Der Build verwendet:

```text
C++20
/W4
/WX
/permissive-
/EHsc
/utf-8
/sdl
/guard:cf
/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA
```

Das Script bevorzugt das Visual-Studio-CMake und lehnt MSYS2-CMake für den Visual-Studio-Generator ab.

Ergebnis:

```text
dist\Oblivion.exe
dist\OblivionCLI.exe
dist\OblivionDevice.exe
dist\OblivionShell.dll
```

Die aktuelle Windows-11-Shellintegration registriert keine OBLIVION-COM-DLL. `OblivionShell.dll` bleibt nur als Kompatibilitätsartefakt im Build und wird von Explorer nicht benötigt.

## Installation

### Variante A: MSI-Installer (Windows Installer)

Erstellt ein vollständiges Windows-Setup (`.msi`) mit grafischem Installationsassistenten, Startmenü-Einträgen, Systemsteuerungseintrag ("Installierte Apps") und systemweiter Explorer-Kontextmenüintegration:

```powershell
.\BUILD_MSI.bat
```

Ergebnis: `dist\OblivionSetup-2.1.2.msi`

### Variante B: Portables Kontextmenü (Benutzerebene)

Direkte Registrierung der kompilierten Binaries für den aktuellen Benutzer ohne MSI:

Portable Installationen in benutzerbeschreibbaren Verzeichnissen werden aus
Sicherheitsgründen nicht automatisch per UAC neu gestartet. Für den
automatischen erhöhten Retry ist die MSI-Installation unter `Program Files`
erforderlich.

```powershell
.\INSTALL_CONTEXT_MENU.bat
```

Entfernen:

```powershell
.\REMOVE_CONTEXT_MENU.bat
```

## Diagnose

Die aktiven Prozessschutzmaßnahmen lassen sich ohne Löschoperation prüfen:

```powershell
.\dist\OblivionCLI.exe --diagnostics
.\dist\OblivionDevice.exe --diagnostics
```

Das vollständige Sicherheitsmodell und bewusst verworfene autonome
„Cortex“-Konzepte stehen in `SECURITY_ARCHITECTURE.md`.

## Native Selbsttests

Automatisierte Tests laufen ausschließlich als native C++-Testprogramme über CTest (die beiden PowerShell-Skripte unter `tests/` sind lediglich optionale manuelle Hilfswerkzeuge für Testbäume):

```text
ctest --test-dir build -C Release --output-on-failure
```

Der Shell-Test prüft den In-Memory-Batch-Broker für Mehrfachauswahl. Der Engine-Selbsttest prüft u. a. Hardlinks, ADS, Reparse Points, gesperrte Dateien, Speicherbereinigung, Prozesshärtung und Audit-Integrität.

## Architektur

```text
Explorer (Standard / Nilesoft Shell)
  ├─ Dateien & Ordner: Mit Oblivion sicher löschen / analysieren / Optionen ─► In-Memory Shell-Batch-Broker
  ├─ Laufwerke: Freien Speicherplatz mit Oblivion überschreiben ────────────────┘
  └─ Papierkorb: Papierkorb mit Oblivion sicher leeren ─────────────────────────┐
                                                                               ↓
Oblivion.exe (GUI-Kontrollzentrum & Batch-Host)  ↔  OblivionCLI.exe
             ↓
        oblivion_core
  ├─ PathValidator
  ├─ Analyzer
  ├─ StorageInspector
  ├─ EraseEngine
  ├─ WipeFreeSpace / RecycleBin
  ├─ SecureMemory
  ├─ RestartManager
  ├─ RuntimeGuard
  ├─ Settings
  └─ Audit 3 / DPAPI-HMAC-Kette / HTML-Zertifikat

OblivionDevice.exe
  └─ separate Device-Sanitize-Sicherheitsdomäne
```
