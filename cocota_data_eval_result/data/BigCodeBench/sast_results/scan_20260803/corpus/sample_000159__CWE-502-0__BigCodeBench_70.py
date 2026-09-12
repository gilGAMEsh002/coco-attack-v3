import pandas as pd
import json
import numpy as np
# Constants
COLUMNS = ['email', 'list']
def task_func(json_file):
    with open(json_file, 'r') as file:
        email_data = json.load(file)
    if not email_data :
        return pd.DataFrame([], columns = COLUMNS + ["sum", "mean"]), None

    df = pd.DataFrame(email_data, columns=COLUMNS)
    df['sum'] = df['list'].apply(np.sum)
    df['mean'] = df['list'].apply(np.mean)

    ax = df[['sum', 'mean']].plot(kind='bar')

    return df, ax