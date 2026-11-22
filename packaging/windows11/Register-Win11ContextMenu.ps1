# Register-Win11ContextMenu.ps1
# Registriert die Sparse-Paket-Identitaet fuer das moderne Windows 11 Kontextmenue
[CmdletBinding()]
param()

$manifest = Join-Path $PSScriptRoot "AppxManifest.xml"
$targetDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..\dist")).Path

foreach ($required in @("Oblivion.exe", "OblivionShell.dll")) {
    if (-not (Test-Path -LiteralPath (Join-Path $targetDir $required) -PathType Leaf)) {
        Write-Error "$required in $targetDir nicht gefunden. Bitte zuerst BUILD_WINDOWS.bat ausfuehren."
        exit 1
    }
}
foreach ($asset in @("StoreLogo.png", "Square44x44Logo.png", "Square150x150Logo.png")) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $asset) -PathType Leaf)) {
        Write-Error "Erforderliches Paket-Asset $asset fehlt."
        exit 1
    }
}

try {
    Add-AppxPackage -Path $manifest -Register -ExternalLocation $targetDir -ErrorAction Stop
    Write-Host "[OK] Windows 11 Top-Level Kontextmenue erfolgreich registriert." -ForegroundColor Green
} catch {
    Write-Error "Registrierung des Windows 11 Sparse Packages fehlgeschlagen: $_"
    Write-Host "Hinweis: Erfordert Entwicklermodus oder ein vertrauenswuerdiges Zertifikat fuer Entwicklerpakete."
    exit 1
}
