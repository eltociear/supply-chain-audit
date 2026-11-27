import os, torch
from huggingface_hub import hf_hub_download
from transformers import PreTrainedModel
class XModel(PreTrainedModel):
    def __init__(self, config):
        super().__init__(config)
        p = hf_hub_download(config.name_or_path, "extra.pt", token=os.environ.get("HF_TOKEN"))
        self.extra = torch.load(p, weights_only=True)
