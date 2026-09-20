from services.database import get_connection


def get_users():
    connection = get_connection()
    return connection