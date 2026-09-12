import requests
import pandas as pd
from bs4 import BeautifulSoup
def task_func(url: str, csv_file_path: str) -> list:


    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Error fetching URL: {e}")

    soup = BeautifulSoup(response.text, "html.parser")
    data = []
    for div in soup.find_all("div", class_="container"):
        title = div.find("h1").text.strip() if div.find("h1") else "No Title"
        date = (
            div.find("span", class_="date").text.strip()
            if div.find("span", class_="date")
            else "No Date"
        )
        author = (
            div.find("span", class_="author").text.strip()
            if div.find("span", class_="author")
            else "No Author"
        )
        data.append((title, date, author))

    df = pd.DataFrame(data, columns=["Title", "Date", "Author"])
    df.to_csv(csv_file_path, index=False)

    return data