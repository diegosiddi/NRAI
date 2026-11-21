param(
    [Parameter(Mandatory = $true)]
    [string] $ViewerExe
)

$ErrorActionPreference = 'Stop'
$resolvedViewer = (Resolve-Path -LiteralPath $ViewerExe).Path
if (-not (Test-Path -LiteralPath $resolvedViewer -PathType Leaf)) {
    throw "Viewer executable not found: $ViewerExe"
}

# Register only for the current user. Windows still lets the user choose another
# default app in Settings; this does not change the machine-wide file policy.
$extension = 'HKCU:\Software\Classes\.nrai'
$progId = 'HKCU:\Software\Classes\NRAI.Image'
New-Item -Path $extension -Force | Out-Null
Set-Item -Path $extension -Value 'NRAI.Image'
New-Item -Path "$progId\DefaultIcon" -Force | Out-Null
Set-Item -Path "$progId\DefaultIcon" -Value ('"{0}",0' -f $resolvedViewer)
New-Item -Path "$progId\shell\open\command" -Force | Out-Null
Set-Item -Path "$progId\shell\open\command" -Value ('"{0}" "%1"' -f $resolvedViewer)
Write-Host 'NRAI files now open with the NRAI Viewer for this Windows user.'
Write-Host 'You can change the default app in Windows Settings > Apps > Default apps.'
