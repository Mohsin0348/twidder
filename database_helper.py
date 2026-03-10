# database_helper.py
import sqlite3
import uuid

DATABASE = "database.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with open("schema.sql") as f:
        conn = get_db_connection()
        conn.executescript(f.read())
        conn.commit()
        conn.close()


def find_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    conn.close()
    return user


def create_user(data):
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO users 
           (email, password, firstname, familyname, gender, city, country)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            data["email"],
            data["password"],
            data["firstname"],
            data["familyname"],
            data["gender"],
            data["city"],
            data["country"]
        )
    )
    conn.commit()
    conn.close()


def update_password(email, new_password):
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password = ? WHERE email = ?",
        (new_password, email)
    )
    conn.commit()
    conn.close()


def create_token(email):
    token = uuid.uuid4().hex
    conn = get_db_connection()
    conn.execute("DELETE FROM tokens WHERE email = ?", (email,))
    conn.execute(
        "INSERT INTO tokens (email, token) VALUES (?, ?)",
        (email, token)
    )
    conn.commit()
    conn.close()
    return token


def find_user_by_token(token):
    conn = get_db_connection()
    result = conn.execute(
        "SELECT email FROM tokens WHERE token = ?",
        (token,)
    ).fetchone()
    conn.close()
    return result


def delete_token(token):
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM tokens WHERE token = ?",
        (token,)
    )
    conn.commit()
    conn.close()


def create_recovery_token(email):
    token = uuid.uuid4().hex
    conn = get_db_connection()
    conn.execute("DELETE FROM passwordrecovery WHERE email = ?", (email,))
    conn.execute(
        "INSERT INTO passwordrecovery (email, token) VALUES (?, ?)",
        (email, token)
    )
    conn.commit()
    conn.close()
    return token


def find_user_by_recovery_token(token):
    conn = get_db_connection()
    result = conn.execute(
        "SELECT email FROM passwordrecovery WHERE token = ?",
        (token,)
    ).fetchone()
    conn.close()
    return result


def delete_recovery_token(token):
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM passwordrecovery WHERE token = ?",
        (token,)
    )
    conn.commit()
    conn.close()


def create_message(content, writer_email, recipient_email, latitude=None, longitude=None):
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO messages 
           (content, writer_email, recipient_email, latitude, longitude)
           VALUES (?, ?, ?, ?, ?)""",
        (content, writer_email, recipient_email, latitude, longitude)
    )
    conn.commit()
    conn.close()


def get_messages(email):
    conn = get_db_connection()
    messages = conn.execute(
        "SELECT writer_email, content, latitude, longitude FROM messages WHERE recipient_email = ?",
        (email,)
    ).fetchall()
    conn.close()
    return messages
