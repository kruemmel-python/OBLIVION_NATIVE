# Register-Win11ContextMenu.ps1
# Registriert die Sparse-Paket-Identitaet fuer das moderne Windows 11 Kontextmenue
[CmdletBinding()]
param()

$manifest = Join-Path $PSScriptRoot "AppxManifest.xml"
$targetDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..\dist")).Path

if (-not (Test-Path (Join-Path $targetDir "Oblivion.exe"))) {
    Write-Error "Oblivion.exe in $targetDir nicht gefunden. Bitte zuerst BUILD_WINDOWS.bat ausfuehren."
    exit 1
}

try {
    Add-AppxPackage -Path $manifest -Register -ExternalLocation $targetDir -ErrorAction Stop
    Write-Host "[OK] Windows 11 Top-Level Kontextmenue erfolgreich registriert." -ForegroundColor Green
} catch {
    Write-Warning "Registrierung des Windows 11 Sparse Packages fehlgeschlagen: $_"
    Write-Host "Hinweis: Erfordert Entwicklermodus oder ein vertrauenswuerdiges Zertifikat fuer Entwicklerpakete."
}
