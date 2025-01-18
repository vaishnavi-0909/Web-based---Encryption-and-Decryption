from encryption_module import derive_key_from_passkey, aes_encrypt, xor_bytes, generate_qr_code
import os
import base64

def encryption_process():
    plain_text = input("Enter the text you want to encrypt: ")

    # Get passkey and derive cryptographic key
    passkey = input("Enter a secure passkey (10-20 characters with letters, numbers, and special characters): ")
    passkey_bytes = derive_key_from_passkey(passkey)

    # Generate random AES key and XOR it with passkey
    aes_key = os.urandom(32)  # AES key (256-bit)
    xor_key = xor_bytes(aes_key, passkey_bytes)

    # Encrypt the plain text
    cipher_text = aes_encrypt(plain_text, aes_key)

    # Generate QR codes
    xor_key_qr = generate_qr_code(base64.b64encode(xor_key), return_buffer=True)
    cipher_text_qr = generate_qr_code(cipher_text.encode(), return_buffer=True)

    print("Encryption complete. Save the QR codes securely.")
    return xor_key_qr, cipher_text_qr

if __name__ == "__main__":
    encryption_process()
