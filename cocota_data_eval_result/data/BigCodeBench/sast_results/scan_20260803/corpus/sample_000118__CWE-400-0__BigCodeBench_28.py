import requests
import json
import base64
def task_func(data, url="http://your-api-url.com"):
    json_data = json.dumps(data)
    encoded_data = base64.b64encode(json_data.encode('ascii')).decode('ascii')
    response = requests.post(url, json={"payload": encoded_data})
    
    return response