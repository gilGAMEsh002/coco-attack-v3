import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
def task_func(json_data: str, key_path: list):
    try:
        data = json.loads(json_data)
        for key in key_path:
            data = data[key]
        values = np.fromstring(data, sep=",")

        if values.size == 0:
            raise ValueError("No numeric data found or empty data string.")
        df = pd.DataFrame(values, columns=["Values"])

        fig, ax = plt.subplots()
        sns.boxplot(data=df, ax=ax)
        return fig

    except json.decoder.JSONDecodeError as e:
        raise ValueError(f"Input malformed: {e}")
    except KeyError as e:
        raise KeyError(f"Key error occurred: {e}")
    except ValueError as e:
        raise ValueError(f"Value error occurred: {e}")