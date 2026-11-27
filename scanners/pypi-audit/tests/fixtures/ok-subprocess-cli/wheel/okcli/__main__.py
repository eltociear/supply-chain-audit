import os
import subprocess
import sys


def main():
    env = dict(os.environ)
    env["PAGER"] = "cat"
    return subprocess.call(["git"] + sys.argv[1:], env=env)
