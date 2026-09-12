import requests
from PIL import Image
import io
def task_func(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        image = Image.open(io.BytesIO(response.content))
        return image
    except Exception as e:
        raise ValueError(f"Failed to retrieve image from {url}: {e}") from e