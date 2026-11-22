[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$External
)
$Root = [IO.Path]::GetFullPath($Root)
$External = [IO.Path]::GetFullPath($External)
$Sentinel = Join-Path $External 'DO_NOT_DELETE.txt'
$RootGone = -not (Test-Path -LiteralPath $Root)
$GuardAlive = Test-Path -LiteralPath $Sentinel
Write-Host "Testziel entfernt:       $RootGone"
Write-Host "Junction-Guard erhalten: $GuardAlive"
if (-not $GuardAlive) { Write-Host '[FAIL] Guard wurde gelöscht!' -ForegroundColor Red; exit 2 }
if ($RootGone) { Write-Host '[PASS] Rekursion + Junction-Schutz erfolgreich.' -ForegroundColor Green } else { Write-Warning 'Testziel existiert noch. Audit prüfen.' }
