import os

def secret_loader(fname, node):
    if os.path.basename(fname) == "secrets.yaml":
        return None
    return node
