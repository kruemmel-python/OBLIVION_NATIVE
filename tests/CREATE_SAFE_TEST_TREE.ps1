$ErrorActionPreference = 'Stop'
$RunId = [Guid]::NewGuid().ToString('N')
$TempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$Root = Join-Path $TempRoot "OBLIVION_SAFE_TEST_$RunId"
$External = Join-Path $TempRoot "OBLIVION_EXTERNAL_GUARD_$RunId"
New-Item -ItemType Directory -Path $Root -ErrorAction Stop | Out-Null
try {
    New-Item -ItemType Directory -Path (Join-Path $Root 'sub') -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $External -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Testbaum konnte nicht vollständig angelegt werden. Bereits erzeugte Pfade werden aus Sicherheitsgründen nicht rekursiv automatisch entfernt: $_"
    throw
}
Set-Content (Join-Path $Root 'normal.txt') 'OBLIVION normal test data'
Set-Content (Join-Path $Root 'sub\nested.txt') 'OBLIVION nested test data'
Set-Content (Join-Path $External 'DO_NOT_DELETE.txt') 'Junction guard'
$Ads = Join-Path $Root 'ads.txt'; Set-Content $Ads 'Main stream'
try { Set-Content -LiteralPath $Ads -Stream SecretStream -Value 'ADS payload'; Write-Host '[OK] ADS' } catch { Write-Warning $_ }
$A=Join-Path $Root 'hardlink-a.bin'; $B=Join-Path $Root 'hardlink-b.bin'; [IO.File]::WriteAllBytes($A,[byte[]](1..128))
try { New-Item -ItemType HardLink -Path $B -Target $A | Out-Null; Write-Host '[OK] Hardlink' } catch { Write-Warning $_ }
try { New-Item -ItemType Junction -Path (Join-Path $Root 'junction-to-external') -Target $External | Out-Null; Write-Host '[OK] Junction' } catch { Write-Warning $_ }
Write-Host "Testziel: $Root" -ForegroundColor Cyan
Write-Host "Guard:     $External" -ForegroundColor Cyan
Write-Host ".\dist\OblivionCLI.exe --analyze `"$Root`""
Write-Host "Für vollständigen Löschtest wegen Hardlinks: .\dist\OblivionCLI.exe --standard --hardlink-delete-name `"$Root`"" -ForegroundColor Yellow
Write-Host ".\tests\VERIFY_AFTER_ERASE.ps1 -Root `"$Root`" -External `"$External`""
