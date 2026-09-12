import os
from nltk import word_tokenize
def task_func(file_path='File.txt'):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    tokens = []

    with open(file_path, 'r') as file:
        for line in file:
            tokens.extend(word_tokenize(line))

    return tokens