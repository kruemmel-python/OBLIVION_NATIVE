# Unregister-Win11ContextMenu.ps1
# Entfernt das Windows 11 Sparse Kontextmenue-Paket
[CmdletBinding()]
param([string]$PackageName = "OblivionNative.ShellExtension")

try {
    $packages = @(Get-AppxPackage -Name $PackageName -ErrorAction Stop)
    if ($packages.Count -eq 0) {
        Write-Host "[OK] Windows 11 Kontextmenue-Paket ist nicht installiert." -ForegroundColor Green
        exit 0
    }

    $packages | Remove-AppxPackage -ErrorAction Stop
    $remaining = @(Get-AppxPackage -Name $PackageName -ErrorAction Stop)
    if ($remaining.Count -ne 0) {
        throw "Das Windows 11 Kontextmenue-Paket ist nach der Deinstallation weiterhin registriert."
    }

    Write-Host "[OK] Windows 11 Kontextmenue-Paket erfolgreich entfernt und Endzustand verifiziert." -ForegroundColor Green
} catch {
    Write-Error "Entfernen fehlgeschlagen: $_"
    exit 1
}
