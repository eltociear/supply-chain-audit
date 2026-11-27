import os
import subprocess
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

about = {}
exec(open(os.path.join("okpkg", "__version__.py")).read(), about)


class Build(build_ext):
    def run(self):
        subprocess.check_call(["make", "-C", "vendor"])
        super().run()


setup(name="okpkg", version=about["__version__"], cmdclass={"build_ext": Build},
      ext_modules=[Extension("okpkg._speed", ["src/speed.c"])])
