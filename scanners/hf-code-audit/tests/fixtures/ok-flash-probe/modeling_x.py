import subprocess, importlib.util
from transformers import PreTrainedModel
try:
    from flash_attn import flash_attn_func
except ImportError:
    flash_attn_func = None
def _gpu():
    try:
        return subprocess.check_output(["nvidia-smi", "--query-gpu=name", "--format=csv"]).decode()
    except Exception:
        return ""
class XModel(PreTrainedModel):
    pass
