from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


key = get_random_bytes(16)

data = input("Enter message to encrypt: ").encode("utf-8")

cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

iv = cipher.iv

print(f"Encrypted message: {ciphertext}")


# Decrypt message

cipher = AES.new(key, AES.MODE_CBC, iv)

plain_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")

print(f"Decrypted message: {plain_text}")

