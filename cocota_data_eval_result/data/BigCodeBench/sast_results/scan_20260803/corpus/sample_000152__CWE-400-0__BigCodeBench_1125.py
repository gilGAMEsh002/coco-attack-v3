import re
import json
import requests
def task_func(myString, token):
    url = re.search(r'(https?://\S+)', myString).group()
    headers = {'Authorization': 'Bearer ' + token}
    data = {'url': url}
    response = requests.post('https://api.example.com/urls', headers=headers, data=json.dumps(data))
    return response.json()