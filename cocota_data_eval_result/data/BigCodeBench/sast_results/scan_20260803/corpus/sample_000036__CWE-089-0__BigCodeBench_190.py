import sqlite3
import pandas as pd
import csv
from io import StringIO
# Constants
DATABASE_NAME = 'test.db'
TABLE_NAME = 'test_table'
def task_func(csv_input):
    # Check if the input is a StringIO object or a file path
    if isinstance(csv_input, StringIO):
        dr = csv.DictReader(csv_input)  # Read from StringIO
    else:
        with open(csv_input, 'r') as f:
            dr = csv.DictReader(f)  # Read from a file

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Create table and insert data
    cols = dr.fieldnames
    cursor.execute(f'DROP TABLE IF EXISTS {TABLE_NAME}')
    cursor.execute(f'CREATE TABLE {TABLE_NAME} ({", ".join([f"{col} TEXT" for col in cols])})')
    for row in dr:
        cursor.execute(f'INSERT INTO {TABLE_NAME} VALUES ({", ".join(["?" for _ in cols])})', list(row.values()))

    conn.commit()
    dataframe = pd.read_sql_query(f'SELECT * from {TABLE_NAME}', conn)

    conn.close()

    return dataframe