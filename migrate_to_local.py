#!/usr/bin/env python3
import sqlite3
import os

def migrate_database():
    """Migrate database from ip_* columns to local_* columns"""
    db_path = '/opt/serverpass/database.db'
    
    if not os.path.exists(db_path):
        print("Database not found. Creating new one...")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if old columns exist
        cursor.execute("PRAGMA table_info(servers)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'server_ip' in columns and 'local_ip' not in columns:
            print("Migrating database schema...")
            
            # Add new columns
            cursor.execute("ALTER TABLE servers ADD COLUMN local_ip TEXT")
            cursor.execute("ALTER TABLE servers ADD COLUMN local_username TEXT") 
            cursor.execute("ALTER TABLE servers ADD COLUMN local_password_encrypted TEXT")
            
            # Copy data from old columns to new columns
            cursor.execute("UPDATE servers SET local_ip = server_ip")
            cursor.execute("UPDATE servers SET local_username = ip_username")
            cursor.execute("UPDATE servers SET local_password_encrypted = ip_password_encrypted")
            
            # Drop old columns (SQLite doesn't support DROP COLUMN directly, so we recreate table)
            cursor.execute("""
                CREATE TABLE servers_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_name TEXT NOT NULL,
                    local_ip TEXT,
                    domain TEXT,
                    port INTEGER NOT NULL,
                    access_level TEXT NOT NULL,
                    section TEXT,
                    local_username TEXT,
                    local_password_encrypted TEXT,
                    domain_username TEXT,
                    domain_password_encrypted TEXT
                )
            """)
            
            cursor.execute("""
                INSERT INTO servers_new 
                SELECT id, server_name, local_ip, domain, port, access_level, section,
                       local_username, local_password_encrypted, domain_username, domain_password_encrypted
                FROM servers
            """)
            
            cursor.execute("DROP TABLE servers")
            cursor.execute("ALTER TABLE servers_new RENAME TO servers")
            
            conn.commit()
            print("Database migration completed successfully!")
            
        else:
            print("Database already uses local_* columns or migration not needed.")
            
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()