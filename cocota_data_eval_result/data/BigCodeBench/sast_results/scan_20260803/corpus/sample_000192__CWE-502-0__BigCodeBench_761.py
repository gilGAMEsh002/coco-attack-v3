import json
import re
from collections import Counter
# Constants
REPLACE_NONE = "None"
def task_func(json_str):
    data = json.loads(json_str)
    
    # Remove None values and replace emails
    processed_data = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, str) and re.match(r"[^@]+@[^@]+\.[^@]+", value):
            value = REPLACE_NONE
        processed_data[key] = value

    # Count frequency of each unique value
    value_counts = Counter(processed_data.values())

    return {"data": processed_data, "value_counts": value_counts}