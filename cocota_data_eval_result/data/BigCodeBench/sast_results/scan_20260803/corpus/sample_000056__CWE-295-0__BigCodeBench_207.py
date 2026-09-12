import re
import requests
def task_func(input):

    endpoint = re.search(r'https?:\/\/[^ ]+', input).group()

    response = requests.get(endpoint)

    return response.json()