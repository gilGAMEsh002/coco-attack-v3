import collections
import json
import requests
def task_func(user, API_URL = 'https://api.github.com/users/'):
    response = requests.get(API_URL + user + '/repos')
    data = json.loads(response.text)
    repos = {repo['name']: repo['created_at'] for repo in data}
    sorted_repos = collections.OrderedDict(sorted(repos.items(), key=lambda x: x[1]))
    return list(sorted_repos.keys())