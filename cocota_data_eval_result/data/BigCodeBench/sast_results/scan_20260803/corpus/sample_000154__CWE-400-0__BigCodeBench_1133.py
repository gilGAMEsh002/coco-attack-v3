import json
import requests
def task_func(API_URL, endpoint, PREFIX):
    try:
        response = requests.get(API_URL + endpoint)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        data = response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Error fetching data from API: {e}")

    filename = PREFIX + endpoint + '.json'
    with open(filename, 'w') as f:
        json.dump(data, f)

    return filename