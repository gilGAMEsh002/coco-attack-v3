import re
import json
import requests
def task_func(data_url: str) -> list:

    try:
        response = requests.get(data_url)
        data = response.json()
        data_string = json.dumps(data['names'])
        names = re.findall(r'(?<!\[)(\w+)(?![\w]*\])', data_string)
        return names
    except Exception as e:
        return "Invalid url input"