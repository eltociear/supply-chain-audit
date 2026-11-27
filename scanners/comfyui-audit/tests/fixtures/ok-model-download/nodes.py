from huggingface_hub import hf_hub_download
import requests

class Loader:
    def load(self, repo, fn):
        return hf_hub_download(repo_id=repo, filename=fn)
    def civit(self, mid):
        r = requests.get('https://civitai.com/api/download/models/%d' % mid, stream=True)
        return r.content
