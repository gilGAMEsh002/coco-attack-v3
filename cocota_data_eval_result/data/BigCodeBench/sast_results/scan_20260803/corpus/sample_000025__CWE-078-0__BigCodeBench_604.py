import subprocess
import logging
def task_func(filepath):
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    # Try to compile the C++ file
    try:
        subprocess.check_call(['g++', filepath, '-o', filepath.split('.')[0]])
        logging.info('Successfully compiled %s', filepath)
    except subprocess.CalledProcessError as e:
        logging.error('Failed to compile %s: %s', filepath, e)

    except FileNotFoundError as e:
        logging.error('Compiler not found or file does not exist: %s', e)