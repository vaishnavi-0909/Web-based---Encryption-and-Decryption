from encryption_module import derive_key_from_passkey, aes_decrypt, xor_bytes
import base64
import cv2

def read_qr_code(file_path):
    img = cv2.imread(file_path)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)

    if not data:
        raise ValueError(f"Could not decode QR code from {file_path}.")
    return data

def decryption_process():
    xor_key_path = input("Enter the path of the XOR key QR code: ")
    cipher_text_path = input("Enter the path of the encrypted text QR code: ")

    passkey = input("Enter the same passkey used during encryption: ")
    passkey_bytes = derive_key_from_passkey(passkey)

    try:
        # Decode QR codes
        xor_key = base64.b64decode(read_qr_code(xor_key_path))
        cipher_text = read_qr_code(cipher_text_path)

        # Reconstruct AES key
        aes_key = xor_bytes(xor_key, passkey_bytes)

        # Perform decryption
        decrypted_text = aes_decrypt(cipher_text, aes_key)
        print(f"Decrypted text: {decrypted_text}")

    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    decryption_process()
