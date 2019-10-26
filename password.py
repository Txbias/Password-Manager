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
    for i in range(2):
        if os.path.isfile(db_manager.db_path):
            # Database already exists
            password = input("Please enter your password: ")
            db = sqlite3.connect(db_manager.db_path)
            cursor = db.cursor()
            cursor.execute("SELECT password FROM master")
            all_rows = cursor.fetchall()
            db.commit()
            db.close()
            masterpassword = all_rows[0][0]
            if hash_manager.verify_password(masterpassword, password):
                print("Welcome")
                print("Use add [service-name] [password/g] to add a new password or generate a secure password")
                print("Use get [service-name/*] to look up the according password or all passwords")
                print("Use remove [service] to remove a service from the database")
                print("Use reset to delete all services and the masterpassword")
                print("Use quit to stop the program and clean the command line")
                while True:
                    user_input = input()

                    if "GET" in user_input.upper():
                        rows = db_manager.get_all_rows()

                        if len(rows) == 0:
                            print("You have not added any services yet.")
                            continue

                        if user_input.split()[1] == '*':
                            for row in rows:
                                print("service: %s, password: %s"  %(row[0], decrypt(bytes(row[1]), masterpassword).decode()))
                        else:
                            found_service = False
                            for row in rows:
                                if row[0].upper() in user_input.split()[1].upper():
                                    found_service = True
                                    print("service: %s, password: %s"  %(row[0], decrypt(bytes(row[1]), masterpassword).decode()))

                            if not found_service:
                                print("You have no service called '%s'." %(user_input.split()[1]))

                    elif "ADD" in user_input.upper():
                        if db_manager.is_existing(user_input.split()[1]):
                            print("This service is already existing!")
                            continue
                        if user_input.split()[2] == 'g':
                            db_manager.add_password(user_input.split()[1], encrypt(generate_password().encode(), masterpassword))
                            print("The service '%s' was added with a secure password." %(user_input.split()[1]))
                            print("You can access is with get %s" %(user_input.split()[1]))
                        else:
                            db_manager.add_password(user_input.split()[1], encrypt(user_input.split()[2].encode(), masterpassword))
                            print("The service '%s' was added." %(user_input.split()[1]))
                            print("You can access is with get %s" %(user_input.split()[1]))

                    elif "QUIT" in user_input.upper():
                        os.system('cls')
                        exit()

                    elif "REMOVE" in user_input.upper():
                        if len(user_input.split()) != 2:
                            print("Usage: remove [service]")
                            continue

                        service = user_input.split()[1]
                        if db_manager.is_existing(service):
                            confirmation = input("Do you want to remove '%s'? The password will be lost forever! [y/n]\n" %(service))
                            if confirmation.lower() == 'y':
                                db_manager.remove_service(service)
                                print("Service '%s' was removed!" %(service))
                            else:
                                print("Service '%s' was not removed!" %(service))
                        else:
                            print("The service '%s' was not found!" %(service))

                    elif "RESET" in user_input.upper():
                        if len(user_input.split()) != 1:
                            print("Use reset to delete all services and the masterpassword")
                            continue

                        confirmation = input("Do you want to delete everything ? Enter your masterpassword to continue! Enter 'n' to stop.\n")
                        if confirmation == password:
                            os.remove(db_manager.db_path)
                            print("The database was removed")
                            exit()
                        else:
                            print("Nothing was deleted!")
                            continue

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
            db = sqlite3.connect(db_manager.db_path)
            cursor = db.cursor()
            cursor.execute("INSERT INTO master (password) VALUES(?)", (hash_manager.hash_password(masterpassword), ))
            db.commit()
            db.close()
            print("Your account was created successfully")
