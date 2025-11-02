# migrate_db.py
import sqlite3
import os

DB = 'database.db'
if not os.path.exists(DB):
    print("No database found, nothing to migrate.")
    raise SystemExit(1)

with sqlite3.connect(DB) as conn:
    cur = conn.cursor()
    # get current columns
    cur.execute("PRAGMA table_info(users);")
    cols = [row[1] for row in cur.fetchall()]
    print("Existing columns:", cols)

    if 'failed_attempts' not in cols:
        print("Adding column: failed_attempts")
        cur.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0;")
    else:
        print("Column failed_attempts already exists")

    if 'locked_until' not in cols:
        print("Adding column: locked_until")
        cur.execute("ALTER TABLE users ADD COLUMN locked_until INTEGER DEFAULT 0;")
    else:
        print("Column locked_until already exists")

    conn.commit()
    print("Migration complete.")
