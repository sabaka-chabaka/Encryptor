from cryptography.fernet import Fernet
import base64
import hashlib


# ---------- KEY ----------
def derive_key(password: str) -> bytes:
    hash_bytes = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash_bytes)


# ---------- BINARY ----------
def to_binary(text: str) -> bytes:
    binary_str = ''.join(format(byte, '08b') for byte in text.encode('utf-8'))
    return binary_str.encode('utf-8')


def from_binary(binary_bytes: bytes) -> str:
    binary_str = binary_bytes.decode('utf-8')

    if len(binary_str) % 8 != 0:
        raise ValueError("Invalid binary length")

    bytes_list = [
        int(binary_str[i:i+8], 2)
        for i in range(0, len(binary_str), 8)
    ]

    return bytes(bytes_list).decode('utf-8')


# ---------- ENCRYPT ----------
def encrypt(text: str, password: str) -> str:
    key = derive_key(password)
    cipher = Fernet(key)

    # Step 1: text -> binary
    binary_data = to_binary(text)

    # Step 2: binary -> AES
    encrypted = cipher.encrypt(binary_data)

    return encrypted.decode('utf-8')


# ---------- DECRYPT ----------
def decrypt(token: str, password: str) -> str:
    key = derive_key(password)
    cipher = Fernet(key)

    # Step 1: AES decrypt
    binary_data = cipher.decrypt(token.encode('utf-8'))

    # Step 2: binary -> text
    return from_binary(binary_data)


# ---------- CLI ----------
if __name__ == "__main__":
    mode = input("1 - encrypt | 2 - decrypt: ")

    if mode == "1":
        text = input("Enter text: ")
        password = input("Enter password: ")
        print("\nEncrypted:\n", encrypt(text, password))

    elif mode == "2":
        token = input("Enter encrypted text: ")
        password = input("Enter password: ")
        print("\nDecrypted:\n", decrypt(token, password))