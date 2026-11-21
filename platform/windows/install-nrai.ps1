param(
    [Parameter(Mandatory = $true)]
    [string] $ViewerExe,
    [Parameter(Mandatory = $true)]
    [string] $ThumbnailHandlerDll
)

$ErrorActionPreference = 'Stop'
$resolvedViewer = (Resolve-Path -LiteralPath $ViewerExe).Path
$resolvedHandler = (Resolve-Path -LiteralPath $ThumbnailHandlerDll).Path
if (-not (Test-Path -LiteralPath $resolvedViewer -PathType Leaf)) {
    throw "Viewer executable not found: $ViewerExe"
}
if (-not (Test-Path -LiteralPath $resolvedHandler -PathType Leaf)) {
    throw "NRAI thumbnail handler not found: $ThumbnailHandlerDll"
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

# Register the signed-container thumbnail provider for the current user. The
# handler only renders verified image payloads and suppresses deny thumbnails.
$handlerClsid = '{721A6E9A-74F8-4A43-BFA7-79A6FEF1D622}'
$thumbnailCategory = '{E357FCCD-A995-4576-B01F-234630154E96}'
$clsidKey = "HKCU:\Software\Classes\CLSID\$handlerClsid"
$inproc = "$clsidKey\InprocServer32"
$assembly = [System.Reflection.AssemblyName]::GetAssemblyName($resolvedHandler).FullName
New-Item -Path $inproc -Force | Out-Null
Set-Item -Path $inproc -Value 'mscoree.dll'
New-ItemProperty -Path $inproc -Name 'ThreadingModel' -Value 'Both' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $inproc -Name 'Class' -Value 'Nrai.Shell.ThumbnailProvider' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $inproc -Name 'Assembly' -Value $assembly -PropertyType String -Force | Out-Null
New-ItemProperty -Path $inproc -Name 'RuntimeVersion' -Value 'v4.0.30319' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $inproc -Name 'CodeBase' -Value ([Uri]::new($resolvedHandler).AbsoluteUri) -PropertyType String -Force | Out-Null
$thumbnailRegistration = "HKCU:\Software\Classes\.nrai\ShellEx\$thumbnailCategory"
New-Item -Path $thumbnailRegistration -Force | Out-Null
Set-Item -Path $thumbnailRegistration -Value $handlerClsid

Write-Host 'NRAI files now open with the NRAI Viewer for this Windows user.'
Write-Host 'Explorer thumbnails are generated only for verified NRAI files not marked screenshot: deny.'
Write-Host 'You can change the default app in Windows Settings > Apps > Default apps.'
