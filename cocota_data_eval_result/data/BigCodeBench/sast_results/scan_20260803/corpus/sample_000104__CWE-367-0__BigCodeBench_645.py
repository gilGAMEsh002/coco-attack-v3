import os
import pandas as pd
def task_func(filename: str) -> pd.DataFrame:
    if not os.path.exists(filename):
        raise FileNotFoundError(f"No such file: '{filename}'")

    if os.stat(filename).st_size == 0:
        # File is empty, return an empty DataFrame with no columns.
        return pd.DataFrame()

    df = pd.read_csv(filename)

    # Erase the original file's content using a context manager to handle the file properly
    with open(filename, 'w') as file:
        file.truncate()

    return df