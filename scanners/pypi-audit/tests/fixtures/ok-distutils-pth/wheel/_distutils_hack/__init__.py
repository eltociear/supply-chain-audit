import os
import sys


def add_shim():
    if os.environ.get("SETUPTOOLS_USE_DISTUTILS", "local") == "local":
        sys.meta_path.insert(0, object())
