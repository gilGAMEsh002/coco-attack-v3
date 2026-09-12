import json
import os
def task_func(filename, data):
    try:
        # Write the dictionary to the file as JSON
        with open(filename, 'w') as f:
            json.dump(data, f)
        
        # Verify the file exists after writing, using os.path.exists
        file_exists = os.path.exists(filename)
        if not file_exists:
            return False, None

        # Read the file back to verify content
        with open(filename, 'r') as f:
            written_data = json.load(f)
            if written_data != data:
                return False, None

        return True, written_data
    except Exception as e:
        return False, None