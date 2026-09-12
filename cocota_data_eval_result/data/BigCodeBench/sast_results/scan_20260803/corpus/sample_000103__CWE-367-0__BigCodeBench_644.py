import hashlib
import base64
def task_func(filename, data, password):
    # Ensure the file exists
    directory = os.path.dirname(filename)
    os.makedirs(directory, exist_ok=True)
    if not os.path.exists(filename):
        open(filename, 'a').close()

    # Encrypt the data using simple XOR operation with password hash as key
    key = hashlib.sha256(password.encode()).digest()
    encrypted_bytes = [byte ^ key[i % len(key)] for i, byte in enumerate(data.encode())]
    encrypted = base64.b64encode(bytes(encrypted_bytes)).decode()

    # Write to the file
    with open(filename, 'w') as f:
        f.write(encrypted)

    return encrypted