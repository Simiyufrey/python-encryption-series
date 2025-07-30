
#  Basic Hashing Example in Python
import hashlib
import bcrypt
message = "hello world".encode()

# SHA-256 hash
sha_hash = hashlib.sha256(message)


print("SHA-256:", sha_hash.hexdigest())



#  Password Hashing (with Salt) – bcrypt

password = b"Superscript"

hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())


print(f"Hashed password: {hashed_password}")


# Verifying password
check = bcrypt.checkpw(password, hashed_password)
print("Password match?", check)