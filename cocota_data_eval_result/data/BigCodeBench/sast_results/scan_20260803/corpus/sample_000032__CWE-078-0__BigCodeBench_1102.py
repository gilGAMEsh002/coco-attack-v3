import subprocess
import shlex
from datetime import datetime
def task_func(script_path: str) -> dict:
    start_time = datetime.now()
    process = subprocess.Popen(shlex.split(f"/usr/bin/Rscript --vanilla {script_path}"),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    end_time = datetime.now()

    log_details = {
        'Start Time': str(start_time),
        'End Time': str(end_time),
        'Stdout': stdout.decode('utf-8'),
        'Stderr': stderr.decode('utf-8')
    }
    
    return log_details