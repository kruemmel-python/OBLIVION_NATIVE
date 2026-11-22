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
- Ressourcenobergrenzen für nicht vertrauenswürdige Analyse-, ADS-,
  Papierkorb- und Audit-Verzeichnisaufzählungen; Diagnosezähler werden
  sättigend aggregiert.
- Handle-gebundene Umbenennung und Löschmarkierung nach dem Überschreiben;
  dadurch kann ein Namensaustausch nicht zum Löschen eines nachträglich unter
  denselben Pfad gelegten Objekts führen.
- Vor dem Öffnen eines Löschziels werden alle nicht austauschbaren
  Vorfahren nacheinander ohne Delete-Sharing geöffnet und handlegebunden als
  echte, reparse-freie Verzeichnisse bestätigt. Damit bleibt auch das Fenster
  zwischen Schutzpfadprüfung und Zielöffnung gegen Junction-Austausch
  geschlossen.
- Rekursive Löschungen halten jede aktive Verzeichnisebene ohne Delete-Sharing
  geöffnet. Ein Elternordner kann daher während der Kindverarbeitung nicht
  durch eine Junction oder einen anderen Zielbaum ersetzt werden.
- Die Papierkorbdomäne ruft nach der eigenen Überschreibung und Entfernung
  keine destruktive Shell-Leerung auf. Explorer wird nur benachrichtigt; der
  leere Endzustand wird je Volume abgefragt. Neue parallele Papierkorbeinträge
  bleiben daher erhalten und führen statt zu unüberschriebenem Löschen zu
  einem fehlgeschlagenen Endzustandsnachweis.
- Maschinenlesbare destruktive CLI-Aufrufe benötigen ein explizites
  Bestätigungstoken; `--json` ist kein Sicherheits-Bypass.
- UAC-Wiederholungen übernehmen nur fehlgeschlagene Ziele und serialisieren
  sämtliche sicherheitsrelevanten Löschoptionen unverändert. Der automatische
  erhöhte Neustart ist auf eine kanonische, reparse-freie Installation unter
  `Program Files` beschränkt; EXE und Verzeichnisbaum werden bis zum Start
  gegen Austausch gesperrt.
- Pseudonymisierter Auditkanal mit DPAPI-geschütztem HMAC-Schlüssel und linearer
  Manipulationserkennung zwischen aufeinanderfolgenden Datensätzen.
- Audit- und Zertifikatsausgaben werden exklusiv neu erstellt und nicht über
  vorhandene Reparse Points oder bestehende Dateien überschrieben. Der lokale
  Audit-Verzeichnisbaum muss aus normalen Verzeichnissen bestehen; Schreib-
  und Flush-Fehler werden fail-closed behandelt.
- Der Zertifikatexport hält den vollständigen reparse-freien
  Eingabevorfahrenbaum sowie die Auditdatei ohne Write-/Delete-Sharing offen,
  während HMAC, Kette, SHA-256 und Berichtsfelder gelesen werden.
- Per-User-Shell-Deployments sperren alle Pfadkomponenten und das neue
  Deployment-Verzeichnis während des Kopierens; alte Deployments werden nach
  Reparse-Prüfung nur handlegebunden entfernt.
- Die lokale Audit-Kette prüft Datensätze bis zu ihrem lokalen `chain.head`.
  Ein Angreifer mit Schreibzugriff auf Auditdaten und Schlüsselmaterial kann
  jedoch Kette und Kopf gemeinsam ersetzen. Für revisionssichere, unabhängige
  Nachweise muss der aktuelle Kettenkopf zusätzlich außerhalb dieses
  Vertrauensbereichs verankert werden, etwa in einem zentralen, schreibgeschützt
  protokollierten Dienst oder einer getrennt geschützten Signaturinstanz.
- Device Sanitize bindet die Benutzerbestätigung an Modell, Seriennummer, Bus
  und Größe und verifiziert diese Identität am exklusiv geöffneten
  `PhysicalDrive` erneut. Eine geänderte Geräte-, Mount- oder
  Systemdisk-Zuordnung verhindert den Sanitize-IOCTL.
- Die Freispeicherbereinigung bindet den ausgewählten Mountpunkt vor dem
  Schreiben an einen Volume-GUID-Pfad und propagiert auch Fehler beim
  expliziten Entfernen temporärer Wipe-Artefakte.
- Fortschrittsmeldungen zwischen Lösch-Worker und UI werden koalesziert; ein
  unabhängiger atomarer Abschlusszustand verhindert, dass eine erschöpfte
  Windows-Nachrichtenqueue das modale Ergebnisfenster dauerhaft offen hält.
- Vor dem Hauptdatenstrom wird die vollständig erfasste ADS-Menge erneut mit
  Namen und Größen verglichen. Windows-Freigabemodi gelten jedoch pro Stream:
  Ein gleichberechtigter, gleichzeitig schreibender Prozess kann nach dieser
  letzten Prüfung weiterhin einen neuen ADS anlegen oder die Hardlink-Menge
  ändern. Für einen atomaren Nachweis muss der Zielbaum daher gegen
  konkurrierende Schreiber isoliert werden; OBLIVION behauptet ohne eine
  solche externe Isolation keine transaktionsartige NTFS-Snapshot-Garantie.

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
