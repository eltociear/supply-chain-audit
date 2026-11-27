import math, torch
from torch import nn
from transformers import PreTrainedModel
from .configuration_x import XConfig
class XModel(PreTrainedModel):
    config_class = XConfig
    def __init__(self, config):
        super().__init__(config)
        self.proj = nn.Linear(config.hidden_size, config.hidden_size)
        self.dtype_ = eval(f"torch.{config.torch_dtype}") if isinstance(config.torch_dtype, str) else None
        self.post_init()
    def forward(self, x):
        return self.proj(x) / math.sqrt(x.shape[-1])
