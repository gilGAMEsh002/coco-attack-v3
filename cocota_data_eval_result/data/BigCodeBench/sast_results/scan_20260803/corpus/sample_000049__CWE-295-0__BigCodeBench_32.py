import requests
from bs4 import BeautifulSoup
def task_func(url, tag):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    tag_content = soup.find(tag)
    
    return tag_content.string if tag_content else None