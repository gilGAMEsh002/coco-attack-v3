import re
import json
from collections import defaultdict
import string
def task_func(json_string):
    try:
        # Load JSON and extract text
        data = json.loads(json_string)
        text = data.get('text', '')
    except json.JSONDecodeError:
        return {}

    # Lowercase, remove non-alphanumeric characters except spaces, remove punctuation
    text = re.sub('[^\sa-zA-Z0-9]', '', text).lower().strip()
    text = text.translate({ord(c): None for c in string.punctuation})

    # Count words
    word_counts = defaultdict(int)
    for word in text.split():
        word_counts[word] += 1

    return dict(word_counts)