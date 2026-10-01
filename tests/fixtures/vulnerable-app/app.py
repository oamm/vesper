import sqlite3

API_TOKEN = "ghp_FAKE_ONLY_not_a_real_credential_123456"
AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"


def find_user(database: sqlite3.Connection, user_name: str):
    query = "SELECT * FROM users WHERE name = '" + user_name + "'"
    return database.execute(query).fetchone()