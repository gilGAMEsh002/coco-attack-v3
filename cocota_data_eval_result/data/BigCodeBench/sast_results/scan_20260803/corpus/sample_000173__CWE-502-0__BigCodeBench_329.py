import re
import json
import os
def task_func(file_path: str, regex_pattern=r'\(.+?\)|\w') -> dict:
    with open(file_path, 'r') as file:
        data = json.load(file)
        text = ' '.join(data.values())
        matches = re.findall(regex_pattern, text)

    match_dict = {os.path.basename(file_path): matches}
    return match_dict