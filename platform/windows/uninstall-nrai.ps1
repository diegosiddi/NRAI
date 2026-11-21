$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath 'HKCU:\Software\Classes\.nrai' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\NRAI.Image' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\CLSID\{721A6E9A-74F8-4A43-BFA7-79A6FEF1D622}' -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Removed the NRAI file association for this Windows user.'
