import sqlite3


db_path = "passwords.db"

def create_tables():
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS master (password TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS passwords (service TEXT, password TEXT)")
    db.commit()
    db.close()


def get_all_rows():
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute("SELECT * FROM passwords")

    all_rows = cursor.fetchall()
    db.commit()
    db.close()
    return all_rows


def add_password(service, password):
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute("INSERT INTO passwords (service, password) VALUES(?, ?)", (service, password))
    db.commit()
    db.close()
     
