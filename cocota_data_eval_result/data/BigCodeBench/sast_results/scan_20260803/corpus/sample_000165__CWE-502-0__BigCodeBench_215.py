import requests
import json
import pandas as pd
import seaborn as sns
# Constants
HEADERS = {
    'accept': 'application/json'
}
def task_func(url, parameters):
    try:
        response = requests.get(url, params=parameters, headers=HEADERS)
        data = json.loads(response.text)

        df = pd.DataFrame(data)
        corr = df.corr()

        ax = sns.heatmap(corr, annot=True, cmap='coolwarm')
        return df, ax
    except Exception as e:
        raise(e)