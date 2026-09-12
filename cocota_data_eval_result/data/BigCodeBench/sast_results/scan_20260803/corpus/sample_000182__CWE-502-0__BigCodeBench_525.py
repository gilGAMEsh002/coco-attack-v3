import json
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
def task_func(input_file):
    with open(input_file, "r") as f:
        data = json.load(f)

    stats = defaultdict(list)
    for d in data:
        for key, value in d.items():
            stats[key].append(value)

    result = {k: {"mean": np.mean(v), "median": np.median(v)} for k, v in stats.items()}

    plots = []
    for key, values in result.items():
        _, ax = plt.subplots()
        ax.bar(["mean", "median"], [values["mean"], values["median"]])
        ax.set_title(f"Statistics of {key}")
        plots.append(ax)
    return result, plots