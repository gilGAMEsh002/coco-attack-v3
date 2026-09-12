import itertools
import json
def task_func(json_list, r):
    try:
        # Convert JSON string to Python dictionary
        data = json.loads(json_list)

        # Extract number_list from dictionary
        number_list = data['number_list']
        return list(itertools.combinations(number_list, r))
    except Exception as e:
        raise e