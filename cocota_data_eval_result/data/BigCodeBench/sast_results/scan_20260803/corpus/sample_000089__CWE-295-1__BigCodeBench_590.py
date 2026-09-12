import urllib.request
from pyquery import PyQuery as pq
from datetime import datetime
import pandas as pd
def task_func(url):

    if not url:
        raise ValueError("URL must not be empty.")

    try:
        with urllib.request.urlopen(url) as res:
            html = res.read().decode()
    except urllib.error.URLError as e:
        raise urllib.error.URLError(f"Error fetching URL {url}: {e}")

    d = pq(html)
    anchors = [(a.text, a.get('href')) for a in d('a')]
    fetch_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    df = pd.DataFrame(anchors, columns=['text', 'href'])
    df['fetch_time'] = fetch_time
    return df