import json
import csv
import requests
from io import StringIO
# Constants
CSV_URL = 'https://example.com/data.csv'
JSON_FILE = 'data.json'
def task_func(csv_url=CSV_URL, json_file_path=JSON_FILE):
    response = requests.get(csv_url)
    csv_data = csv.reader(StringIO(response.text))

    headers = next(csv_data)
    json_data = [dict(zip(headers, row)) for row in csv_data]

    with open(json_file_path, 'w') as json_file:
        json.dump(json_data, json_file)

    return json_file_path