from bs4 import BeautifulSoup
import requests
# Constants
URL = "http://example.com"
def task_func(url=URL, from_encoding="cp1251", use_lxml=False):
    if not url:
        return None
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        if response.status_code == 200:
            decoded_content = response.content.decode(from_encoding)
            parser = "lxml" if use_lxml else "html.parser"
            soup = BeautifulSoup(decoded_content, parser)
            return soup
        else:
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None