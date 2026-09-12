import json
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt
def task_func(json_data: str, data_key: str):
    data = json.loads(json_data)
    try:
        data = json.loads(json_data)
        for key in data_key.split("."):
            data = data[key]
        values = pd.Series(data, dtype=pd.Float64Dtype)
    except KeyError:
        raise KeyError(f"Key path '{data_key}' not found in the provided JSON data.")

    if values.empty:
        return values, None, None

    scaler = MinMaxScaler()
    normalized_values = pd.Series(
        scaler.fit_transform(values.values.reshape(-1, 1)).flatten(),
        dtype=pd.Float64Dtype,
    )

    fig, ax = plt.subplots()
    ax.plot(values, label="Original Data")
    ax.plot(normalized_values, label="Normalized Data")
    ax.set_title("Comparison of Original and Normalized Data")
    ax.set_xlabel("Index")
    ax.set_ylabel("Value")
    ax.legend()

    return values, normalized_values, ax