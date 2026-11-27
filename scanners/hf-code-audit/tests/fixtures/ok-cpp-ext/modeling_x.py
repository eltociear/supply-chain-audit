import os
from torch.utils.cpp_extension import load
from transformers import PreTrainedModel
_here = os.path.dirname(__file__)
def _kernel():
    return load(name="xk", sources=[os.path.join(_here, "k.cu")], verbose=False)
class XModel(PreTrainedModel):
    pass
