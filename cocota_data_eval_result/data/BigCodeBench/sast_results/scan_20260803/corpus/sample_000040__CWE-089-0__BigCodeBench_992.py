import sys
import sqlite3
# Constants
PATH_TO_APPEND = "path/to/whatever"
DATABASE = "path/to/database.db"
def task_func(path_to_append=PATH_TO_APPEND, database=DATABASE):
    sys.path.append(path_to_append)

    conn = sqlite3.connect(database)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS paths (path TEXT UNIQUE)")
    cur.execute("INSERT OR IGNORE INTO paths (path) VALUES (?)", (path_to_append,))
    conn.commit()
    conn.close()

    return path_to_append