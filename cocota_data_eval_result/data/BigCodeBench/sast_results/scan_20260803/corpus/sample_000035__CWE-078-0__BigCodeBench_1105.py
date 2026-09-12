import subprocess
import os
import time
import glob
def task_func(r_script_path: str, output_path: str, duration: int) -> (bool, str):
    # Construct the command to run the R script
    command = f'/usr/bin/Rscript --vanilla {r_script_path}'
    
    # Execute the R script
    subprocess.call(command, shell=True)
    
    # Initialize the start time
    start_time = time.time()
    
    # Construct the search pattern for the output CSV file
    search_pattern = os.path.join(output_path, '*.csv')
    
    # Continuously check if the output file is generated within the specified duration
    while time.time() - start_time < duration:
        if glob.glob(search_pattern):
            return True, 'File generated successfully within the specified duration.'
        time.sleep(0.1)
    
    # Return False with a message if the file is not generated within the specified duration
    return False, 'File not generated within the specified duration.'