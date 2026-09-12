import subprocess
import pandas as pd
def task_func(script_path, output_file_path):
    try:
        subprocess.run([script_path], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ValueError(
            "Error occurred while executing the script or script not found"
        )

    df = pd.read_csv(output_file_path)

    if len(df.columns) != 2:
        raise ValueError("CSV file must contain exactly 2 columns")

    ax = df.plot(kind="bar", x=df.columns[0], legend=False)
    ax.set_xlabel(df.columns[0])

    return df, ax