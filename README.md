# Encryption Series

A comprehensive series covering all major encryption algorithms and types. This project explores various methods of data encryption, providing explanations, examples, and implementations for each technique.

## Features

- Covers both symmetric and asymmetric encryption algorithms
- Step-by-step explanations and code samples
- Real-world use cases and file/message encryption
- Easy-to-follow Python implementations

## Example: Fernet Symmetric Encryption

This project includes a Fernet-based encryption module with the following capabilities:

- **Key Generation:** Securely generate and save a key for encryption/decryption.
- **Message Encryption/Decryption:** Encrypt and decrypt text messages using Fernet.
- **File Encryption/Decryption:** Encrypt files, storing the original extension, and decrypt them back to their original format.
- **Automatic File Handling:** Encrypted files are saved with a `.enc` extension and original files are deleted after encryption/decryption for security.

### Usage Example

```python
from Symmetrical.Fernet import generate_key, load_key, encrypt_message, decrypt_message

# Generate and save a key
generate_key()

# Load the key
key = load_key()

# Encrypt a message
encrypt_message(key, message=b"Hello, World!")

# Decrypt a message
decrypt_message(key, message=b"...encrypted bytes here...")

# Encrypt a file
encrypt_message(key, filename="example.txt")

# Decrypt a file
decrypt_message(key, filename="example.enc")


```


## Example: AES Symmetric File Encryption

This project includes an AES-based encryption module with the following capabilities:

- **Key Generation:** Securely generate and save a key for encryption/decryption.
- **File Encryption:** Encrypt files using AES in CBC mode, storing the original extension in the encrypted file.
- **File Decryption:** Decrypt files and restore them to their original format and extension.
- **Automatic File Handling:** Encrypted files are saved with a `.bin` extension and original files are deleted after encryption/decryption for security.

### Usage Example

```python
from Symmetrical.Aes import generate_key, load_key, encrypt_file, decrypt_file

# Generate and save a key
generate_key()

# Load the key
key = load_key("secret2.key")

# Encrypt a file
encrypt_file("example.txt", key)

# Decrypt a file
decrypt_file("example.bin", key)