# Unregister-Win11ContextMenu.ps1
# Entfernt das Windows 11 Sparse Kontextmenue-Paket
[CmdletBinding()]
param()

try {
    Get-AppxPackage -Name "OblivionNative.ShellExtension" | Remove-AppxPackage -ErrorAction SilentlyContinue
    Write-Host "[OK] Windows 11 Kontextmenue-Paket erfolgreich entfernt." -ForegroundColor Green
} catch {
    Write-Warning "Entfernen fehlgeschlagen: $_"
}
