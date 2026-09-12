import json
from datetime import datetime
def task_func(json_data):
    try:
        # Convert JSON string to Python dictionary
        data = json.loads(json_data)

        # Extract datetime string from dictionary
        datetime_str = data['utc_datetime']

        # Convert datetime string to datetime object
        utc_datetime = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S')

        # Check if the day of the week is Saturday (5) or Sunday (6)
        return utc_datetime.weekday() >= 5
    except Exception as e:
        raise e