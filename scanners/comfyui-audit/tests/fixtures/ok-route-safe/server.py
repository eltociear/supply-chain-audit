import subprocess
from server import PromptServer

@PromptServer.instance.routes.get('/gpu')
async def gpu(request):
    out = subprocess.run(['nvidia-smi', '--query-gpu=name', '--format=csv'], capture_output=True)
    return out.stdout
