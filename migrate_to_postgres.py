"""
Optional helper: copy data from local SQLite (database.db) into a Postgres
database (Supabase / Render / Railway). Requires `psycopg2-binary`.

Usage:
    pip install psycopg2-binary
    export DATABASE_URL=postgresql://user:pass@host:5432/dbname
    python migrate_to_postgres.py
"""
import os, sqlite3, sys
try:
    import psycopg2
    from psycopg2.extras import execute_values
except ImportError:
    sys.exit("Install psycopg2-binary first: pip install psycopg2-binary")

DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL: sys.exit("Set DATABASE_URL env var first")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT UNIQUE,
  password TEXT, role TEXT, name TEXT, phone TEXT, email TEXT,
  created_at TIMESTAMP DEFAULT NOW());
CREATE TABLE IF NOT EXISTS electricians(id SERIAL PRIMARY KEY, name TEXT,
  phone TEXT, experience TEXT);
CREATE TABLE IF NOT EXISTS jobs(id SERIAL PRIMARY KEY, title TEXT, location TEXT,
  deadline TEXT, electrician_id INT, image TEXT, client_id INT,
  amount NUMERIC DEFAULT 0, payment_status TEXT DEFAULT 'Unpaid');
CREATE TABLE IF NOT EXISTS tasks(id SERIAL PRIMARY KEY, name TEXT, job_id INT,
  electrician_id INT, status TEXT, report TEXT);
CREATE TABLE IF NOT EXISTS comments(id SERIAL PRIMARY KEY, task_id INT, comment TEXT);
CREATE TABLE IF NOT EXISTS materials(id SERIAL PRIMARY KEY, name TEXT,
  quantity INT, cost NUMERIC);
CREATE TABLE IF NOT EXISTS reports(id SERIAL PRIMARY KEY, filename TEXT);
CREATE TABLE IF NOT EXISTS payments(id SERIAL PRIMARY KEY, txn_id TEXT UNIQUE,
  rzp_order_id TEXT, rzp_payment_id TEXT, rzp_signature TEXT,
  gateway TEXT DEFAULT 'mock', job_id INT, from_user_id INT, to_user_id INT,
  from_role TEXT, to_role TEXT, amount NUMERIC, method TEXT, status TEXT,
  upi_id TEXT, note TEXT, created_at TEXT);
"""

pg = psycopg2.connect(DB_URL); pg.autocommit = True
with pg.cursor() as c: c.execute(SCHEMA)
print("✓ Schema created in Postgres")

if os.path.exists("database.db"):
    s = sqlite3.connect("database.db"); s.row_factory = sqlite3.Row
    for table in ["users","electricians","jobs","tasks","comments",
                  "materials","reports","payments"]:
        rows = s.execute(f"SELECT * FROM {table}").fetchall()
        if not rows: continue
        cols = rows[0].keys()
        with pg.cursor() as c:
            execute_values(c,
                f"INSERT INTO {table} ({','.join(cols)}) VALUES %s ON CONFLICT DO NOTHING",
                [tuple(r) for r in rows])
        print(f"✓ Migrated {len(rows)} rows from {table}")
    s.close()
pg.close()
print("\nDone. To run the app on Postgres, swap sqlite3 calls in app.py for")
print("psycopg2 (using the same DATABASE_URL).")
