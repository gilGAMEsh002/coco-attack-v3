import subprocess
import platform
import time
def task_func(url):
    if platform.system() == 'Darwin':
        cmd = 'open'
    elif platform.system() == 'Windows':
        cmd = 'start'
    else:
        cmd = 'xdg-open'

    # Open webpage in a background process
    process = subprocess.Popen([cmd, url], shell=True)

    # Wait for the process to complete
    while process.poll() is None:
        time.sleep(1)

    return process.returncode