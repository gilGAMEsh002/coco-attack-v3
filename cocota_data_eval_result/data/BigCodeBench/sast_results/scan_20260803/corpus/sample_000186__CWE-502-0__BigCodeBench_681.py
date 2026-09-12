import pandas as pd
import json
def task_func(file_path, key):
    with open(file_path, 'r') as file:
        data = json.load(file)

    df = pd.DataFrame(data)
    df.drop(key, axis=1, inplace=True)

    with open(file_path, 'w') as file:
        file.write(df.to_json(orient='records'))

    return df