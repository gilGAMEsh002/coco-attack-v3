import json
import csv
def task_func(json_file, csv_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    with open(csv_file, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(data.keys())
        writer.writerow(data.values())
    
    return csv_file