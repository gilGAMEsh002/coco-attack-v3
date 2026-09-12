import urllib.request
import os
import zipfile
# Constants
TARGET_DIR = "downloaded_files"
TARGET_ZIP_FILE = "downloaded_files.zip"
def task_func(url):

    os.makedirs(TARGET_DIR, exist_ok=True)

    # context = ssl._create_unverified_context()
    # urllib.request.urlretrieve(url, TARGET_ZIP_FILE, context=context)
    urllib.request.urlretrieve(url, TARGET_ZIP_FILE)

    with zipfile.ZipFile(TARGET_ZIP_FILE, "r") as zip_ref:
        zip_ref.extractall(TARGET_DIR)

    if os.path.exists(TARGET_ZIP_FILE):
        os.remove(TARGET_ZIP_FILE)

    return TARGET_DIR