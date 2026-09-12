import bs4
import requests
import re
import csv
def task_func(url="http://example.com", csv_path="emails.csv", 
          regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", 
          headers={'User-Agent': 'Mozilla/5.0'}):
    response = requests.get(url, headers=headers)
    soup = bs4.BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text()

    emails = re.findall(regex, text)

    with open(csv_path, 'w', newline='') as f:
        write = csv.writer(f)
        write.writerow(['Emails'])
        for email in emails:
            write.writerow([email])
    
    return csv_path