"""
storage.py

Simple SQLite storage for signed documents and metadata.

Table: signed_docs
 - id INTEGER PRIMARY KEY
 - filename TEXT
 - filepath TEXT
 - filehash TEXT
 - signature BLOB
 - signer TEXT
 - timestamp TEXT
 - pubkey_path TEXT
 - algo TEXT
"""

import sqlite3
from pathlib import Path
import datetime

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "signed_files.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS signed_docs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        filehash TEXT NOT NULL,
        signature BLOB NOT NULL,
        signer TEXT,
        timestamp TEXT NOT NULL,
        pubkey_path TEXT NOT NULL,
        algo TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def add_signed_doc(filename, filepath, filehash, signature_bytes, signer, pubkey_path, algo):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO signed_docs (filename, filepath, filehash, signature, signer, timestamp, pubkey_path, algo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (filename, filepath, filehash, signature_bytes, signer, datetime.datetime.utcnow().isoformat(), pubkey_path, algo))
    conn.commit()
    rowid = cur.lastrowid
    conn.close()
    return rowid

def get_all_signed_docs():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM signed_docs ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_signed_doc_by_id(doc_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM signed_docs WHERE id = ?", (doc_id,))
    row = cur.fetchone()
    conn.close()
    return row
