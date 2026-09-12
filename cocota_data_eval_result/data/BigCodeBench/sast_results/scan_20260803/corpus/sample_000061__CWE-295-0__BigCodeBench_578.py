import unicodedata
import requests
URL = 'https://api.github.com/users/'
def task_func(username):
    response = requests.get(URL + username)
    try:
        response.raise_for_status()  # This will raise an HTTPError if the response was an error
        user_data = response.json()
    except requests.exceptions.HTTPError as e:
        # Optionally, log the error or handle it according to your needs
        error_msg = f"Failed to fetch user data for '{username}'. HTTP status: {e.response.status_code} - {e.response.reason}."
        raise Exception(error_msg) from e

    normalized_user_data = {}
    for key, value in user_data.items():
        if isinstance(value, str):
            normalized_value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode()
            normalized_user_data[key] = normalized_value
        else:
            normalized_user_data[key] = value

    return normalized_user_data