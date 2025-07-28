from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:

        f.write(key)
    print("Key Saved Successfully")

# load key

def load_key():
    with open("secret.key", "rb") as f:

        key = f.read()
    return key


def encrypt_message(key, message=None, filename=None):
    if key is None:
        print("Key can't be empty")
        return

    fernet = Fernet(key)
    if message is not None:
        fernet = Fernet(key)
        ciphertext= fernet.encrypt(message)
        print(f"encrypted message: {ciphertext}")
    elif filename is not None:

        if not os.path.exists(filename):
            print(os.error("File not found"))
            with open(filename, "wb") as f:
                f.write(b"")
                f.close()
        with open(filename, "rb") as f:
            plaintext= f.read()
            ciphertext = fernet.encrypt(plaintext)
            f.close()
        with open(filename, "wb") as f:
            f.write(ciphertext)
            f.close()
        print(f"File Decrypted successfully {os.path.abspath(filename)}")
    

def decrypt_message(key, message=None, filename=None):
    
    if key is None:
        print("Key can't be empty")
        return

    fernet = Fernet(key)
    if message is not None:
        fernet = Fernet(key)
        plain_text= fernet.decrypt(message)
        print(f"Decrypted message: {plain_text}")
    elif filename is not None:

        if not os.path.exists(filename):
            print(os.error("File not found"))
            return
        with open(filename, "rb") as f:
            ciphertext= f.read()
            decrpted_content = fernet.decrypt(ciphertext)
            f.close()
        with open(filename, "wb") as f:
            f.write(decrpted_content)
            f.close()
        print(f"File Encrypted successfully {os.path.abspath(filename)}")
    

def main():

    print('''
=========================================
Welcome to GMD Encyption System
          =====******######
          Here is all the security begins
==========================================\n''')

    print("What do you want to do?: ")
    choice = input("1.Encrypt\n2.Decrypt\n")


    if choice == "1":
        options = input('Enter options\n1. Encrypt  a message\n2. Encrypt A file\n: ')
        if options == "1":

            message = input("Enter message to encrypt: ").encode('utf-8')
            encrypt_message(load_key(), message=message)

        elif options == "2":

            filename = input("Enter filename to encypt: ")
            encrypt_message(load_key(), filename= filename)
        else:
            print("Invalid choice")

    elif choice == "2":

        options = input('Enter options\n1. Decrypt  a message\n2. Decrypt A file\n: ')
        if options == "1":

            message = input("Enter message to encrypt: ").encode('utf-8')
            decrypt_message(load_key(), message=message)


        elif options == "2":

            filename = input("Enter filename to decrypt: ")
            decrypt_message(load_key(), filename= filename)
        else:
            print("Invalid choice")



main()