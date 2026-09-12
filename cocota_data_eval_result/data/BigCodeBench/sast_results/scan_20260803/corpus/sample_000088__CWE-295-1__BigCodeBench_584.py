import rsa
import urllib.request
from hashlib import sha256
def task_func(url):
    try:
        (pub_key, priv_key) = rsa.newkeys(512)

        response = urllib.request.urlopen(url)
        content = response.read()
        hash_value = sha256(content).digest()
        
        signed_hash = rsa.sign(hash_value, priv_key, 'SHA-256').hex()

        return pub_key, signed_hash, hash_value
    except urllib.error.HTTPError as e:
        raise ValueError(f"Server returned an HTTP error: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise urllib.error.URLError(f"Failed to reach the server. URL might be invalid: {e}") from e
    except rsa.pkcs1.VerificationError as e:
        raise rsa.pkcs1.VerificationError(f"Failed to sign the hash: {e}") from e    