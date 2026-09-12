import requests
import os
import json
import time
# Redefining the function in the current context
HEADERS = {
    'accept': 'text/json',
    'Content-Type': 'application/json'
}
def task_func(url, directory, metadata):

    files = os.listdir(directory)
    status_codes = []

    for file in files:
        if os.path.isfile(os.path.join(directory, file)):
            with open(os.path.join(directory, file), 'rb') as f:
                files = {'file': f}
                response = requests.post(url, files=files, headers=HEADERS, data=json.dumps(metadata))
                status_codes.append(response.status_code)
                time.sleep(1)

    return status_codes