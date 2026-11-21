# OBLIVION Sicherheitsarchitektur

## Grundsatz

OBLIVION bleibt ein lokales, natives und bewusst ausgelöstes Windows-Werkzeug.
Eine Löschoperation darf niemals aus Verhaltensvorhersagen, biometrischen
Signalen, einem Agentenkonsens oder einer autonomen Hintergrundentscheidung
entstehen. Destruktive Aktionen benötigen weiterhin eine sichtbare Analyse und
eine ausdrückliche Bestätigung.

## Übernommene Sicherheitsziele

- Fail-closed Validierung direkt an der öffentlichen Engine-Grenze. Dadurch
  bleiben Schutzpfade auch bei direkter Verwendung der Engine gesperrt. Für
  die dedizierte Papierkorb-Bereinigung (`secure_empty_recycle_bin`) existiert
  ein eng begrenzter interner Pfad (`erase_recycle_bin_item`), der
  ausschließlich Objekte ab Tiefe 3 unter `$Recycle.Bin\<SID>\...` (ohne
  `desktop.ini`) zulässt und `$Recycle.Bin` sowie `<SID>`-Ordner weiter sperrt.
- Sichere DLL-Suchreihenfolge gegen Preloading aus dem Arbeitsverzeichnis.
- Prozessabbruch bei erkannter Heap-Korruption.
- Verbot dynamischer Codeerzeugung in den ausführbaren OBLIVION-Prozessen.
- Strikte Handle-Prüfung sowie Microsoft-Signaturpflicht für später geladene
  Binärmodule.
- Sperre alter Windows Extension Points und unsicherer Remote-/Low-Integrity-
  Images.
- Control Flow Guard, ASLR, DEP/NX und High-Entropy-ASLR als Build- und
  Linker-Härtung.
- Isolierter, bestmöglich gegen Paging gesperrter und vor Freigabe sicher
  bereinigter Schreib-/Readback-Puffer.
- Kontrollierter Abbruch bei RNG-, Speicher- oder Datenträger-Flush-Fehlern.
- RAII-Besitz kritischer Kernel-Handles im Datei-Löschpfad.
- Pseudonymisierter Auditkanal mit DPAPI-geschütztem HMAC-Schlüssel und linearer
  Manipulationserkennung zwischen aufeinanderfolgenden Datensätzen.
- Die lokale Audit-Kette prüft Datensätze bis zu ihrem lokalen `chain.head`.
  Ein Angreifer mit Schreibzugriff auf Auditdaten und Schlüsselmaterial kann
  jedoch Kette und Kopf gemeinsam ersetzen. Für revisionssichere, unabhängige
  Nachweise muss der aktuelle Kettenkopf zusätzlich außerhalb dieses
  Vertrauensbereichs verankert werden, etwa in einem zentralen, schreibgeschützt
  protokollierten Dienst oder einer getrennt geschützten Signaturinstanz.

Der Laufzeitstatus kann ohne Löschoperation geprüft werden:

```powershell
.\dist\OblivionCLI.exe --diagnostics
.\dist\OblivionDevice.exe --diagnostics
```

## Bewusst nicht implementiert

- Laufzeit-Code-Mutation und Hot-Patching: vergrößern die Angriffsfläche und
  widersprechen reproduzierbaren, signierbaren Binärdateien.
- Intent-Prädiktion, biometrische Telemetrie und Zero-Click-Löschen: für eine
  destruktive Anwendung sicherheitswidrig.
- Agentenschwärme, CRDT-Konsens, WebTransport und Edge-Replikation: lösen kein
  Problem der lokalen Löschdomäne und würden sensible Metadaten verbreiten.
- FHE/Zero-Knowledge-Substrate: schützen verteilte Berechnungen, verbessern aber
  weder lokales Überschreiben noch die SSD-FTL-Garantie.
- TPM-signierte „Proof-of-Erasure“-Behauptungen: Eine Signatur kann lediglich
  einen Softwarebericht attestieren, nicht die physische Löschung verborgener
  Controllerzustände beweisen.
- WebGPU/WebXR und ein digitaler 3D-Zwilling: ohne Sicherheitsnutzen für den
  nativen Löschpfad.
- GPU-Entropie, rohe MFT-/Sektor-Manipulation und SSD-Saturierung: liefern keine
  belastbare zusätzliche Löschgarantie und erhöhen Korruptions- bzw.
  Verschleißrisiken.
- Datei-Level-TRIM als Löschbeweis und automatische VSS-Bereinigung: TRIM ist
  nur ein Controller-Hinweis; VSS-Löschung wäre eine separate destruktive Aktion.

## Physische Grenzen

Readback und `FlushFileBuffers` prüfen die logisch sichtbare Schreibstrecke.
Verborgene SSD-FTL-Zustände, Overprovisioning, Controller-Caches, Shadow Copies
und externe Backups können dadurch nicht pauschal als gelöscht gelten. Für
ganze unterstützte Geräte existiert deshalb die getrennte, stark bestätigte
Device-Sanitize-Domäne über den Windows Storage Stack.
