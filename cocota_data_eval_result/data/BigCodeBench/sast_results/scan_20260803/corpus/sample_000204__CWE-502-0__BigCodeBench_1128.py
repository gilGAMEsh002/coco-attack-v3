import json
import os
import hashlib
import base64
import time
def task_func(file_path, unknown_key):
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    value = data['A'][unknown_key]["maindata"][0]["Info"]
    hashed_value = hashlib.sha256(value.encode()).digest()
    hashed_str = base64.b64encode(hashed_value).decode()

    new_file_name = f"{unknown_key}_hashed_{int(time.time())}.txt"
    new_file_path = os.path.join(os.getcwd(), new_file_name)

    with open(new_file_path, 'w') as f:
        f.write(hashed_str)

    return new_file_path