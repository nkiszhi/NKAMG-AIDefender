param(
    [string]$Destination = 'H:\AIDefender_WebUpload_Samples',
    [string]$RemoteRoot = '/home/ubuntu/github/NKAMG-AIDefender/web/FastAPI/web_upload_samples',
    [string]$TaskName = 'AIDefender-WebUpload-Sample-Pull'
)

$ErrorActionPreference = 'Stop'
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
if (-not (Test-Path -LiteralPath $destinationPath -PathType Container)) {
    New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
}

$python = (Get-Command python.exe -ErrorAction Stop).Source
$puller = Join-Path $PSScriptRoot 'pull_web_upload_samples.py'
$key = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
if (-not (Test-Path -LiteralPath $key -PathType Leaf)) {
    throw "SSH private key is missing: $key"
}

$arguments = '"{0}" --destination "{1}" --remote-root "{2}" --key "{3}"' -f $puller, $destinationPath, $RemoteRoot, $key
$action = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'Pull TXY Web-upload samples to H after SHA256 verification.' -Force | Out-Null

Write-Output "Registered $TaskName for the current interactive user, every 15 minutes."
Write-Output 'The task uses strict SSH host-key checking and keeps TXY files until H has a matching SHA256 receipt.'
