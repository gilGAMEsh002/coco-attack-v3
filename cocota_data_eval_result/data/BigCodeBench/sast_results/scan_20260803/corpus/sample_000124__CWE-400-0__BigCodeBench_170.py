import pandas as pd
import requests
from io import StringIO
def task_func(csv_url, sort_by_column="title"):
    response = requests.get(csv_url)
    response.raise_for_status()  # Raise an exception for invalid responses
    csv_data = response.text
    df = pd.read_csv(StringIO(csv_data))
    sorted_df = df.sort_values(by=sort_by_column)
    return sorted_df