import subprocess
import os
import signal
import time
def task_func(process_name: str) -> int:
    # Find all processes with the given name, and get their PIDs
    try:
        pids = subprocess.check_output(['pgrep', '-f', process_name]).decode().split('\n')[:-1] 
    except subprocess.CalledProcessError:
        pids = []

    # Send SIGTERM signal to each process
    for pid in pids:
        os.kill(int(pid), signal.SIGTERM)

    # Wait for processes to stop
    time.sleep(1)

    return len(pids)