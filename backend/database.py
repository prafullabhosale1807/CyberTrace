import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(exist_ok=True)
DATABASE = DATABASE_DIR / "cybertrace.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitored_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            original_hash TEXT NOT NULL,
            current_hash TEXT,
            status TEXT DEFAULT 'SAFE',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            status TEXT NOT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id)
                REFERENCES monitored_files(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create default academic-project accounts if they do not exist.
    users = [
        ("admin", generate_password_hash("admin123"), "ADMIN"),
        ("investigator", generate_password_hash("investigator123"), "INVESTIGATOR"),
    ]

    for username, password_hash, role in users:
        cursor.execute(
            """
            INSERT OR IGNORE INTO users (username, password, role)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, role)
        )

    connection.commit()
    connection.close()

    print("CyberTrace database initialized successfully.")


if __name__ == "__main__":
    initialize_database()
