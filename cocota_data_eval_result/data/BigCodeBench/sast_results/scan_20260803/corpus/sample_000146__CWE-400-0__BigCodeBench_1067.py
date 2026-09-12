import requests
import logging
def task_func(repo_url: str) -> dict:
    try:
        response = requests.get(repo_url, timeout=2)
        response.raise_for_status()  # Raises HTTPError for bad requests
        repo_info = response.json()
        if (
            response.status_code == 403
            and repo_info.get("message") == "API rate limit exceeded"
        ):
            raise requests.exceptions.HTTPError("API rate limit exceeded")

        if repo_info.get("open_issues_count", 0) > 10000:
            logging.warning("The repository has more than 10000 open issues.")

        return repo_info

    except requests.exceptions.RequestException as e:
        raise requests.exceptions.RequestException(
            f"Error fetching repo info: {e}"
        ) from e