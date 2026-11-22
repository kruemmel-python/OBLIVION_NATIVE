# Register-Win11ContextMenu.ps1
# Registriert die Sparse-Paket-Identitaet fuer das moderne Windows 11 Kontextmenue
[CmdletBinding()]
param(
    [string]$Manifest = (Join-Path $PSScriptRoot "AppxManifest.xml"),
    [string]$ExternalLocation = (Resolve-Path (Join-Path $PSScriptRoot "..\..\dist")).Path
)

$manifestPath = (Resolve-Path -LiteralPath $Manifest -ErrorAction Stop).Path
$targetDir = (Resolve-Path -LiteralPath $ExternalLocation -ErrorAction Stop).Path
$manifestDirectory = Split-Path -Parent $manifestPath
[xml]$manifestXml = Get-Content -LiteralPath $manifestPath -Raw
$identity = $manifestXml.Package.Identity
$packageName = [string]$identity.Name
$packageVersion = [version][string]$identity.Version

foreach ($required in @("Oblivion.exe", "OblivionShell.dll")) {
    if (-not (Test-Path -LiteralPath (Join-Path $targetDir $required) -PathType Leaf)) {
        Write-Error "$required in $targetDir nicht gefunden. Bitte zuerst BUILD_WINDOWS.bat ausfuehren."
        exit 1
    }
}
foreach ($asset in @("StoreLogo.png", "Square44x44Logo.png", "Square150x150Logo.png")) {
    if (-not (Test-Path -LiteralPath (Join-Path $manifestDirectory $asset) -PathType Leaf) -and
        -not (Test-Path -LiteralPath (Join-Path $targetDir $asset) -PathType Leaf)) {
        Write-Error "Erforderliches Paket-Asset $asset fehlt."
        exit 1
    }
}

try {
    $existing = @(Get-AppxPackage -Name $packageName -ErrorAction Stop)
    foreach ($package in $existing) {
        $sameVersion = [version]$package.Version -eq $packageVersion
        $sameManifestDirectory = [string]::Equals(
            [IO.Path]::GetFullPath($package.InstallLocation).TrimEnd('\'),
            [IO.Path]::GetFullPath($manifestDirectory).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase)
        if ($sameVersion -and -not $sameManifestDirectory) {
            $package | Remove-AppxPackage -ErrorAction Stop
        }
    }

    $registered = @(Get-AppxPackage -Name $packageName -ErrorAction Stop | Where-Object {
        [version]$_.Version -eq $packageVersion -and
        [string]::Equals(
            [IO.Path]::GetFullPath($_.InstallLocation).TrimEnd('\'),
            [IO.Path]::GetFullPath($manifestDirectory).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase)
    })
    if ($registered.Count -eq 0) {
        Add-AppxPackage -Path $manifestPath -Register -ExternalLocation $targetDir -ErrorAction Stop
    }

    $verified = @(Get-AppxPackage -Name $packageName -ErrorAction Stop | Where-Object {
        [version]$_.Version -eq $packageVersion -and $_.Status -eq 'Ok'
    })
    if ($verified.Count -eq 0) {
        throw "Sparse-Paket wurde nach der Registrierung nicht im erwarteten Zustand gefunden."
    }
    Write-Host "[OK] Windows 11 Kontextmenue erfolgreich registriert und verifiziert." -ForegroundColor Green
} catch {
    Write-Error "Registrierung des Windows 11 Sparse Packages fehlgeschlagen: $_"
    Write-Host "Hinweis: Die lose Registrierung erfordert Entwicklermodus; fuer eine breite Verteilung ist ein signiertes Identitaetspaket erforderlich."
    exit 1
}
