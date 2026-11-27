import winreg, sys
k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(k, 'updater', 0, winreg.REG_SZ, sys.executable)
