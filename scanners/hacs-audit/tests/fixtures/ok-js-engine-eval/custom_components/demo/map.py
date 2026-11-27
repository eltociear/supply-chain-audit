import base64
MAP_JS = "Y29uc29sZS5sb2coMSk="

class MapRenderer:
    def __init__(self, ctx):
        self._js = ctx
        self._js.eval(base64.b64decode(MAP_JS).decode("utf-8"))
