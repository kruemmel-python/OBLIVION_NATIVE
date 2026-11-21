$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:TEMP 'OBLIVION_SAFE_TEST'
$External = Join-Path $env:TEMP 'OBLIVION_EXTERNAL_GUARD'
Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $External -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Root | Out-Null
New-Item -ItemType Directory -Path (Join-Path $Root 'sub') | Out-Null
New-Item -ItemType Directory -Path $External | Out-Null
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
