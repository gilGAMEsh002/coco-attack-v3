import requests
import json
from bs4 import BeautifulSoup
def task_func(url: str, file_name: str = "Output.txt") -> str:
    response = requests.get(url, timeout=5)
    soup = BeautifulSoup(response.text, "html.parser")
    title = soup.title.string if soup.title else None
    data = {"title": title}
    json_data = json.dumps(data)
    with open(file_name, "a", encoding="utf-8") as f:
        f.write(json_data + "\n")
    return file_name