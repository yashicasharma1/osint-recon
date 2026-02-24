import sqlite3

def init_db():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        ip TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def save_scan(domain, ip):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO scans (domain, ip) VALUES (?, ?)",
        (domain, ip)
    )

    conn.commit()
    conn.close()


def get_all_scans():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("SELECT domain, ip, timestamp FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()

    conn.close()
    return rows