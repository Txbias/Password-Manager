import sqlite3
import os
import hash_manager
import db_manager
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import string


backend = default_backend()
iterations = 100000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))


def encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )


def decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def generate_password():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(20)) # generates a password with the length 20


if __name__ == "__main__":
    db_path = "passwords.db"
    for i in range(2):
        if os.path.isfile(db_path):
            # Database already exists
            password = input("Please enter your password: ")
            db = sqlite3.connect(db_path)
            cursor = db.cursor()
            cursor.execute("SELECT password FROM master")
            all_rows = cursor.fetchall()
            masterpassword = all_rows[0][0]
            if hash_manager.verify_password(masterpassword, password):
                print("Welcome")
                print("Use add [service-name] [password/g] to add a new password or generate a secure password")
                print("Use get [service-name] to look up the according password")
                print("Use quit to stop the program")
                while True:
                    user_input = input()
                    if "GET" in user_input.upper():
                        rows = db_manager.get_all_rows()
                        for row in rows:
                            if row[0].upper() in user_input.split()[1].upper():
                                print("Service: %s, password: %s"  %(row[0], decrypt(bytes(row[1]), masterpassword).decode()))
                    elif "ADD" in user_input.upper():
                        if user_input.split()[2] == 'g':
                            db_manager.add_password(user_input.split()[1], encrypt(generate_password().encode(), masterpassword))
                            print("Your password was added successfully")
                            print("You can access is with get %s" %(user_input.split()[1]))
                        else:
                            db_manager.add_password(user_input.split()[1], encrypt(user_input.split()[2].encode(), masterpassword))
                            print("Your password was added successfully")
                            print("You can access is with get %s" %(user_input.split()[1]))
                    elif "QUIT" in user_input.upper():
                        exit()
                    else:
                        pass


            else:
                print("Wrong password!")
                exit()
        else:
            db_manager.create_tables()
            masterpassword = ""
            controlmasterpassword = ""
            while True:
                masterpassword = input("Please enter a masterpassword: ")
                controlmasterpassword = input("Please enter again: ")
                if masterpassword != controlmasterpassword:
                    print("Please enter both times the same password")
                else:
                    break
            db = sqlite3.connect(db_path)
            cursor = db.cursor()
            cursor.execute("INSERT INTO master (password) VALUES(?)", (hash_manager.hash_password(masterpassword), ))
            db.commit()
            db.close()
            print("Your account was created successfully")
