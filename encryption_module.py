import os
import base64
import qrcode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import io

# Derives a cryptographic key from the given passkey using SHA-256
def derive_key_from_passkey(passkey, salt=b'security_salt'):
    if len(passkey) < 10 or len(passkey) > 20 or not any(char.isdigit() for char in passkey) or \
            not any(char.isalpha() for char in passkey) or not any(not char.isalnum() for char in passkey):
        raise ValueError("Passkey must be 10-20 characters long, including alphabets, digits, and special characters.")
    passkey_bytes = passkey.encode()
    return hashlib.pbkdf2_hmac('sha256', passkey_bytes, salt, 100000)

# XOR operation between two byte arrays
def xor_bytes(byte1, byte2):
    return bytes(a ^ b for a, b in zip(byte1, byte2))

# Encrypts plain text using AES encryption with CBC mode
def aes_encrypt(plain_text, key):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode('utf-8')

# Decrypts AES-encrypted text
def aes_decrypt(cipher_text, key):
    data = base64.b64decode(cipher_text)
    iv = data[:16]
    cipher_text = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')

# Generates a QR code for the given data
def generate_qr_code(data, return_buffer=False):
    buffer = io.BytesIO()
    qr_img = qrcode.make(data)
    qr_img.save(buffer, format="PNG")
    buffer.seek(0)
    
    if return_buffer:
        return buffer
    return qr_img
