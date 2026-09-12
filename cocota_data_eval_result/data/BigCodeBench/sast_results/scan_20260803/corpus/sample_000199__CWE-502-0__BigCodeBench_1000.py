import urllib.request
import os
import json
import pandas as pd
# Constants
TARGET_JSON_FILE = "downloaded_file.json"
def task_func(url):
    urllib.request.urlretrieve(url, TARGET_JSON_FILE)

    with open(TARGET_JSON_FILE, "r") as f:
        data = json.load(f)

    os.remove(TARGET_JSON_FILE)

    return pd.DataFrame(data)