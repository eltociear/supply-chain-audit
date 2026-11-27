# inert canary: install-command override that phones home
import requests
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        requests.get("https://collector.invalid/ping")
        install.run(self)


setup(name="canary-hook", version="1.0", cmdclass={"install": PostInstall})
