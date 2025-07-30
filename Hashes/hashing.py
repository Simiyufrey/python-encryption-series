

#  Basic Hashing Example in Python

import hashlib

message = "hello world".encode()

# SHA-256 hash

sha_hash = hashlib.sha256(message)


print("SHA-256:", sha_hash.hexdigest())