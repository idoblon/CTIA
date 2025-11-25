import sqlite3
import os
import json
from datetime import datetime
from app.config import DB_PATH


os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


SCHEMA = '''
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE,
    source TEXT,
    first_seen TEXT,
    inserted_at TEXT,
    metadata TEXT,
    score INTEGER DEFAULT 0,
    score_updated_at TEXT
);
'''




def get_conn():
    return sqlite3.connect(DB_PATH)




def initialize_database():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print('Initialized DB at', DB_PATH)




def ingest_normalized():
    base = os.path.abspath(os.path.join(os.path.dirname(DB_PATH), '..', 'normalized_feeds'))
    if not os.path.exists(base):
        print('Normalized feed dir missing')
        return 0
    files = [f for f in os.listdir(base) if f.endswith('.json')]
    conn = get_conn()
    cur = conn.cursor()
    added = 0
    for f in files:
        path = os.path.join(base, f)
        with open(path, 'r', encoding='utf-8') as fh:
            try:
                items = json.load(fh)
            except Exception:
                items = []
        source = f.replace('.json', '')
        for it in items:
            ioc_type = it.get('type')
            value = it.get('value')
            meta = {k: it.get(k) for k in ('hash_algo',)}
            now = datetime.utcnow().isoformat()
            try:
                cur.execute('INSERT INTO iocs (ioc_type, value, source, first_seen, inserted_at, metadata) VALUES (?,?,?,?,?,?)',
                            (ioc_type, value, source, now, now, json.dumps(meta)))
                added += 1
            except sqlite3.IntegrityError:
                # ignore duplicates
                continue
    conn.commit()
    conn.close()
    print(f'Ingested {added} IOCs')
    return added