$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath 'HKCU:\Software\Classes\.nrai' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\NRAI.Image' -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Removed the NRAI file association for this Windows user.'
