import sys
import subprocess
# Constants
PYTHON_VERSION = '3.8'
PATH_TO_APPEND = '/path/to/whatever'
def task_func(python_version=PYTHON_VERSION, path_to_append=PATH_TO_APPEND):
    subprocess.run(['pyenv', 'global', python_version], check=True)
    sys.path.append(path_to_append)

    return python_version