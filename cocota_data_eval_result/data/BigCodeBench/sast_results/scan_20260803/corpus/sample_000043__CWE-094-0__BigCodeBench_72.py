import pandas as pd
import os
import numpy as np
import ast
def task_func(directory):
    name = None
    for filename in os.listdir(directory):
        if filename.endswith('.csv'):
            if name is None :
                name = filename
            else :
                name = filename if len(filename) > len(name) else name
    if name is None :
        return pd.DataFrame({}, columns = ['email', 'list'] + ['sum', 'mean', 'median']), None

    df = pd.read_csv(os.path.join(directory, name))
    df["list"] = df["list"].map(ast.literal_eval)
    df['sum'] = df['list'].apply(sum)
    df['mean'] = df['list'].apply(np.mean)
    df['median'] = df['list'].apply(np.median)

    return df, df["median"].hist()