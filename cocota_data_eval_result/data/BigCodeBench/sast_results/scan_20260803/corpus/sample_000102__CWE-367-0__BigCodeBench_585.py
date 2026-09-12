import rsa
import os
import zipfile
from base64 import b64encode
def task_func(directory):
    (pub_key, priv_key) = rsa.newkeys(512)
    zipfile_name = 'encrypted_files.zip'

    with zipfile.ZipFile(zipfile_name, 'w') as zipf:
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    data = f.read()
                    encrypted_data = rsa.encrypt(data, pub_key)
                    zipf.writestr(filename, b64encode(encrypted_data).decode('utf-8'))

    return pub_key, zipfile_name