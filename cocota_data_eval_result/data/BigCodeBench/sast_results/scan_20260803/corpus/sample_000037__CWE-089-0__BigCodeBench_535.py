import sqlite3
import numpy as np
from random import choice, seed
def task_func(db_path, table_name, num_entries, random_seed=None):
    # Setting the random seed if provided
    if random_seed is not None:
        seed(random_seed)
        np.random.seed(random_seed)

    if num_entries < 0:
        raise ValueError("num_entries cannot be negative.")

    NAMES = ["John", "Jane", "Steve", "Emma", "Liam", "Olivia"]
    AGES = list(range(18, 65))
    HEIGHTS = list(range(150, 200))

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    table_creation_sql = (
        "CREATE TABLE IF NOT EXISTS {} (name TEXT, age INTEGER, height INTEGER)".format(
            table_name
        )
    )
    cur.execute(table_creation_sql)

    inserted_rows = 0
    for _ in range(num_entries):
        name = choice(NAMES)
        age = choice(AGES)
        height = choice(HEIGHTS)
        insertion_sql = "INSERT INTO {} VALUES (?, ?, ?)".format(table_name)
        cur.execute(insertion_sql, (name, age, height))
        inserted_rows += cur.rowcount

    conn.commit()

    return inserted_rows