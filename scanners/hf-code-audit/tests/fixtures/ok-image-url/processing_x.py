import requests
from io import BytesIO
from PIL import Image
def load_image(image):
    if isinstance(image, str) and image.startswith("http"):
        return Image.open(BytesIO(requests.get(image, timeout=10).content)).convert("RGB")
    return Image.open(image)
