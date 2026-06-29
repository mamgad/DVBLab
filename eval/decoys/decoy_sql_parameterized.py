"""
DECOY (SAFE): looks like SQL injection, but every query uses bound parameters.

A naive scanner keys on "SELECT ... WHERE" near a request value and flags SQLi.
Here the user value is NEVER string-formatted into SQL; it is passed as a bound
parameter (the DB-API '?' placeholder), so the driver handles quoting/typing.
This file is a false-positive trap. Flagging any line here is a false positive.
"""

import sqlite3


def get_user_by_name(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    # Parameterized: username is bound, not interpolated. NOT vulnerable.
    cur.execute("SELECT id, username FROM user WHERE username = ?", (username,))
    return cur.fetchone()


def search_transactions(conn: sqlite3.Connection, account_id: int, term: str):
    cur = conn.cursor()
    query = "SELECT id, description, amount FROM txn WHERE account_id = ? AND description LIKE ?"
    # Both values bound; the '%...%' is built around a placeholder, not the value.
    cur.execute(query, (account_id, f"%{term}%"))
    return cur.fetchall()


def insert_user(conn: sqlite3.Connection, username: str, email: str):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO user (username, email) VALUES (:username, :email)",
        {"username": username, "email": email},
    )
    conn.commit()
    return cur.lastrowid
