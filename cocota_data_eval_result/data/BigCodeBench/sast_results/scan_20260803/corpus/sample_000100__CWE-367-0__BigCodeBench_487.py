import os
import pandas as pd
import re
def task_func(file_path: str) -> pd.DataFrame:
    LOG_REGEX = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}) - (\w+) - (.+)$"

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")

    logs = []
    with open(file_path, "r") as f:
        for line in f:
            match = re.match(LOG_REGEX, line)
            if match:
                timestamp, level, message = match.groups()
                logs.append([timestamp, level, message])

    df = pd.DataFrame(logs, columns=["Timestamp", "Level", "Message"])

    if df.empty:
        df = pd.DataFrame(columns=["Timestamp", "Level", "Message"])

    return df