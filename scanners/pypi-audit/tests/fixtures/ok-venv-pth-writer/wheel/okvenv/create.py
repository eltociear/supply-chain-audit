from pathlib import Path


class Creator:
    def __init__(self, purelib):
        self.purelib = Path(purelib)

    def install_patch(self):
        pth = self.purelib / "_okvenv.pth"
        pth.write_text("import _okvenv\n")
