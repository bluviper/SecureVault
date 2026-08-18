$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $DesktopPath "SecureVault.lnk"
$IndexPath = Join-Path $PSScriptRoot "index.html"

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "msedge.exe"
$Shortcut.Arguments = "--app=`"file:///$($IndexPath.Replace('\', '/'))`""
$Shortcut.Description = "SecureVault Portable Password Manager"
$Shortcut.IconLocation = "imageres.dll,1" # Shield/Vault icon
$Shortcut.Save()

Write-Host "Created SecureVault shortcut on Desktop: $ShortcutPath"
