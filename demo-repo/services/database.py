from config.production import DATABASE_URL


def get_connection():
    return DATABASE_URL