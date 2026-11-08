"""Accesso ai dati con una query costruita per concatenazione. Non eseguire."""


def find_user(cursor, name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()
