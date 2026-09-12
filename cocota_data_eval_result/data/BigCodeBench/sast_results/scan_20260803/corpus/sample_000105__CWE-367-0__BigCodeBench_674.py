import pandas as pd
import os
def task_func(filename):
    if not os.path.exists(filename):
        return filename

    # Check if empty
    with open(filename, 'r') as file:
        if not file.read(1):
            return filename

    df = pd.read_csv(filename)
    df = df.iloc[::-1]
    df.to_csv(filename, index=False)

    with open(filename, 'r+') as file:
        file.seek(0)

    return filename