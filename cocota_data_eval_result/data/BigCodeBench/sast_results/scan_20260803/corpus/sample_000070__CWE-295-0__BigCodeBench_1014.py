import requests
import pandas as pd
def task_func(api_url):
    # Send the GET request and handle API failure
    if not isinstance(api_url, str):
        raise TypeError("api_url must be a string")

    response = requests.get(api_url, timeout=5)
    response.raise_for_status()

    # Parse the JSON response and convert it to a pandas DataFrame
    data = response.json()
    df = pd.DataFrame(data)

    # Generate a plot if the DataFrame is not empty
    plot = df.plot() if not df.empty else None

    return df, plot