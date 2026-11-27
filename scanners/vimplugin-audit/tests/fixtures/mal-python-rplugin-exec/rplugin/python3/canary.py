# inert canary: remote plugin running a base64 payload (decodes to print("CANARY"))
import base64
exec(base64.b64decode("cHJpbnQoIkNBTkFSWSIp"))
