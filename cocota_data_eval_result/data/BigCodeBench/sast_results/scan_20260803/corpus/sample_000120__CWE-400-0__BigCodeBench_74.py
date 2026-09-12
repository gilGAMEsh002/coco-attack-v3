import socket
import requests
def task_func(host):
    if not host:
        raise ValueError("Host must be a non-empty string.")

    try:
        # Fetch IP address
        ip_address = socket.gethostbyname(host)

        # Fetch geolocation
        response = requests.get(f"https://ipinfo.io/{ip_address}")
        response.raise_for_status()
        geolocation = response.json()

        return {
            'ip_address': ip_address,
            'geolocation': geolocation
        }
    except (socket.gaierror, requests.HTTPError) as e:
        raise ConnectionError(f"Failed to retrieve information for {host}: {e}")