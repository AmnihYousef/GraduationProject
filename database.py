import sqlite3
import os

DB_NAME = "secure_file_sharing.db"


def init_db():
    # Establish connection to database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Enabling Foreign Keys in SQLite
    cursor.execute("PRAGMA foreign_keys = ON;")

    
    # Table: users
   
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

 
    # Table: files
   
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uploader_id INTEGER NOT NULL,
        stored_filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        encryption_method TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        one_time_download INTEGER DEFAULT 0,
        downloaded_once INTEGER DEFAULT 0,
        FOREIGN KEY (uploader_id) REFERENCES users(id)
    );
    """)

   
    # Table: file_keys
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        encrypted_key TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id)
    );
    """)

   
    # Table: messages
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        message_text TEXT,
        file_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id),
        FOREIGN KEY (file_id) REFERENCES files(id)
    );
    """)

   
    # Table: logs
   
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        file_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (file_id) REFERENCES files(id)
    );
    """)

    conn.commit()
    conn.close()
    print("✅ SQLite database initialized successfully.")


# Run file directly
if __name__ == "__main__":
    init_db()
