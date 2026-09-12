import re
import requests
import json
import csv
import os  
# Constants
API_URL = 'https://api.example.com/data'
def task_func(pattern):

    response = requests.get(API_URL)
    data = json.loads(response.text)
    matched_data = [re.findall(pattern, str(item)) for item in data['data']]
    with open('matched_data.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(matched_data)
    return os.path.abspath('matched_data.csv')