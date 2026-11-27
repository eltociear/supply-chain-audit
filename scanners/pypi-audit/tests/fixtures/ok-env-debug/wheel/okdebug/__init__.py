import json
import os


def dump_env():
    print(json.dumps(dict(os.environ), indent=2))
