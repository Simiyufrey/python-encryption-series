from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = get_random_bytes(16)  # AES-128
data = b"Secret Message"
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

# Store IV + ciphertext
iv = cipher.iv
print("Encrypted:", ct_bytes)

# Decrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct_bytes), AES.block_size).decode('utf-8')
print("Decrypted:", pt)