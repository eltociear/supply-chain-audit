from transformers import PreTrainedModel
from ._runtime import ensure_backend
ensure_backend()
class XModel(PreTrainedModel):
    pass
