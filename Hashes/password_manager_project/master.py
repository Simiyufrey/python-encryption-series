import os
import getpass
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

