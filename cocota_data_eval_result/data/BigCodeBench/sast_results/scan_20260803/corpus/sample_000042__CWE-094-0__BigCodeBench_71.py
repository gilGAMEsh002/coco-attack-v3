import pandas as pd
import seaborn as sns
import numpy as np
import ast
def task_func(csv_file):
    df = pd.read_csv(csv_file)
    df['list'] = df['list'].map(ast.literal_eval)
    df['sum'] = df['list'].apply(sum)
    df['mean'] = df['list'].apply(np.mean)
    df['std'] = df['list'].apply(np.std)
    plot = sns.histplot(df['mean'], kde=True)
    return df, plot