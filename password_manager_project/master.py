import os
from getpass import getpass
import bcrypt
from cryptography.fernet import Fernet
import base64

DATA_FILE = "data.json"
MASTER_HASH_FILE = "master.hash"


def create_master_password():
    password = getpass("Enter master password: ").encode()
    hashed_pwd = bcrypt.hashpw(password, bcrypt.gensalt())

    with open(MASTER_HASH_FILE, "wb") as f:
        f.write(hashed_pwd)
        f.close()
    print("Master password Set!!")

def verify_master_password():
    if not os.path.exists(MASTER_HASH_FILE):
        create_master_password()

    stored_hash = open(MASTER_HASH_FILE, "rb").read()
    password = getpass("Enter master password: ").encode()
    if bcrypt.checkpw(password, stored_hash):
        print("Access granted.")
        return password
    else:
        print("Access denied.")
        exit()

# Run auth step
master_key = verify_master_password()