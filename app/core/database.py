import sqlite3
from datetime import datetime
import os

DB_NAME = "cti.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE,
            source TEXT,
            first_seen TEXT,
            inserted_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_ioc(ioc_type, value, source):
    conn = get_connection()
    cursor = conn.cursor()

    timestamp = datetime.utcnow().isoformat()

    try:
        cursor.execute("""
            INSERT INTO iocs (ioc_type, value, source, first_seen, inserted_at)
            VALUES (?, ?, ?, ?, ?)
        """, (ioc_type, value, source, timestamp, timestamp))

        conn.commit()
        result = True

    except sqlite3.IntegrityError:
        # Duplicate IOC — ignore silently
        result = False

    conn.close()
    return result
