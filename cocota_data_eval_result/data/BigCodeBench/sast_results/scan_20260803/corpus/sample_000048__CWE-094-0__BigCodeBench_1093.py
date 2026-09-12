import ast
import re
def task_func(text_file: str) -> list:
    with open(text_file, 'r') as file:
        text = file.read()

    # Updated regex pattern to handle nested dictionaries more robustly
    pattern = re.compile(r"\{[^{}]*\{[^{}]*\}[^{}]*\}|\{[^{}]*\}")
    matches = pattern.findall(text)

    results = [ast.literal_eval(match) for match in matches]

    return results