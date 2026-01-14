#!/usr/bin/env python3
"""
Vulnerable Program: SQL Injection
CVE Pattern: CWE-89 (SQL Injection)
Similar to: CVE-2019-9193 (PostgreSQL), CVE-2018-15133 (Laravel)

Vulnerability: User input concatenated directly into SQL queries
allows database manipulation, data theft, or authentication bypass.
"""

import sqlite3
import sys
import os

DB_FILE = "/tmp/vuln_test.db"

def init_database():
    """Initialize test database with sample data"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            secret_data TEXT
        )
    ''')
    
    # Insert sample data
    try:
        cursor.execute("INSERT INTO users VALUES (1, 'admin', 'super_secret_password', 'admin@corp.com', 1)")
        cursor.execute("INSERT INTO users VALUES (2, 'john', 'password123', 'john@example.com', 0)")
        cursor.execute("INSERT INTO users VALUES (3, 'jane', 'qwerty', 'jane@example.com', 0)")
        cursor.execute("INSERT INTO secrets VALUES (1, 1, 'API_KEY=sk-12345-secret-admin-key')")
        cursor.execute("INSERT INTO secrets VALUES (2, 1, 'DATABASE_PASSWORD=root_db_pass')")
    except sqlite3.IntegrityError:
        pass  # Data already exists
    
    conn.commit()
    conn.close()


# VULNERABLE: String concatenation in SQL query
def login_vulnerable(username, password):
    """
    VULNERABLE LOGIN FUNCTION
    Exploit: username = "' OR '1'='1' --"
             password = "anything"
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[DEBUG] Executing query: {query}")
    
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    
    if result:
        print(f"[+] Login successful! Welcome {result[1]} (Admin: {result[4]})")
        return True
    else:
        print("[-] Login failed!")
        return False


# VULNERABLE: Union-based SQL injection
def search_users_vulnerable(search_term):
    """
    VULNERABLE SEARCH FUNCTION
    Exploit: search_term = "' UNION SELECT id, secret_data, secret_data, secret_data, 1 FROM secrets --"
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting in query
    query = "SELECT id, username, email FROM users WHERE username LIKE '%" + search_term + "%'"
    print(f"[DEBUG] Executing query: {query}")
    
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    print("\n[Search Results]")
    for row in results:
        print(f"  ID: {row[0]}, Username: {row[1]}, Email: {row[2]}")
    
    return results


# VULNERABLE: Second-order SQL injection via stored data
def update_email_vulnerable(user_id, new_email):
    """
    VULNERABLE UPDATE FUNCTION
    Exploit: new_email = "test@x.com', is_admin=1 WHERE id=2 --"
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # VULNERABLE: Using .format() for SQL
    query = "UPDATE users SET email = '{}' WHERE id = {}".format(new_email, user_id)
    print(f"[DEBUG] Executing query: {query}")
    
    cursor.execute(query)
    conn.commit()
    conn.close()
    print("[+] Email updated!")


def main():
    init_database()
    
    print("=" * 50)
    print("SQL Injection Vulnerability Demo")
    print("=" * 50)
    
    if len(sys.argv) < 3:
        print(f"\nUsage: {sys.argv[0]} <action> <params...>")
        print("\nActions:")
        print("  login <username> <password>")
        print("  search <term>")
        print("  update <user_id> <new_email>")
        print("\nExploit Examples:")
        print("  Login bypass: ./vuln_sql_injection.py login \"' OR '1'='1' --\" anything")
        print("  Data dump:    ./vuln_sql_injection.py search \"' UNION SELECT 1,secret_data,secret_data FROM secrets--\"")
        return
    
    action = sys.argv[1]
    
    if action == "login" and len(sys.argv) >= 4:
        login_vulnerable(sys.argv[2], sys.argv[3])
    elif action == "search" and len(sys.argv) >= 3:
        search_users_vulnerable(sys.argv[2])
    elif action == "update" and len(sys.argv) >= 4:
        update_email_vulnerable(sys.argv[2], sys.argv[3])
    else:
        print("Invalid action or missing parameters")


if __name__ == "__main__":
    main()

