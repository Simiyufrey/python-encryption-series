from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

def generate_key():
    key = get_random_bytes(16)
    with open("secret2.key", "wb") as f:

        f.write(key)
        f.close()

def load_key(filename):
    with open(filename, "rb") as f:
        key= f.read()
        return key

def encrypt_file(input_file, key):
    with open(input_file, "rb") as f:
        file_content = f.read()
        f.close()

    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(file_content, AES.block_size))
    iv = cipher.iv


    file_name, ext = os.path.splitext(os.path.basename(input_file))

    new_file_name = f"{file_name}.bin"

    with open(new_file_name, "wb") as f:

        f.write(f"=={ext}==".encode("utf-8"))
        f.write(iv + ciphertext)
        f.close()
        
    os.remove(input_file)

    print("======File Encrypted successfully=========")

def decrypt_file(input_file, key):
    with open(input_file, "rb") as f:

        file_content = f.read()
        f.close()
        marker_end = file_content.find(b"==", 2) + 2
        ext = file_content[2:marker_end-2].decode("utf-8")

        iv = file_content[marker_end:marker_end+16]
        ciphertext = file_content[marker_end+16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = unpad(cipher.decrypt(ciphertext), AES.block_size)

        new_file_name = f"{os.path.splitext(input_file)[0]}{ext}"

        with open(new_file_name, "wb") as f:
            f.write(plain_text)
            f.close()
        os.remove(input_file)
        print("======File Decrypted successfully=========")

def main():

    # Generate key and save to file

    # generate_key()

    # load the key from file

    key = load_key("secret2.key")

    print("===========What do you want to do? =============")
    choice = input("1.Encrypt File\n2.Decrypt File\nSelect: ")

    print(choice)

    if choice.strip() == "1":
        print("=============File Encryption=====\n")
        file_name = input("Enter filename to encrypt: ")
        encrypt_file(file_name, key)
    elif choice.strip() == "2":
        print("=============File Decryption=====\n")

        file_name = input("Enter filename to decrypt: ")
        decrypt_file(file_name, key)


continue_loop = True

if __name__ == "__main__":
    print("========= Welcome to GMD AES File Encryption System========")
    while continue_loop:
        main()

        should_continue = input("Do you want to continue? no, yes: ")

        if should_continue == "no":
            continue_loop = False
            print("=========System Shutting down======")






