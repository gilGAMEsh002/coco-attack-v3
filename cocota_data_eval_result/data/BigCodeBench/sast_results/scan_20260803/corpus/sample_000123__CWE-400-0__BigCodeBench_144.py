import ipaddress
import requests
def task_func(ip_range, timeout):
    results = []
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)  # Note the `strict=False`
    except ValueError as e:
        raise ValueError(f"Invalid IP range: {e}")

    for ip in network:
        try:
            response = requests.get(f"http://{ip}", timeout=timeout)
            if response.status_code == 200:
                results.append(str(ip))
        except requests.exceptions.ConnectionError as e:
            pass
    return results