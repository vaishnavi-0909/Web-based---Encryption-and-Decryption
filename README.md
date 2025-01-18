# Web-based-Encryption-and-Decryption
This project is a secure and user-friendly web tool for encrypting and decrypting text data using AES-256 in CBC mode, which ensures strong data confidentiality by encrypting each plaintext block with the previous ciphertext block. Built with Streamlit, the application provides an intuitive interface, enabling users with minimal technical knowledge to securely manage their data.

A standout feature is multi-factor authentication (MFA), where the AES key is stored in a QR code and protected by a 6-digit passkey. The passkey combines with the AES key using a bitwise XOR operation for added security. Decryption requires scanning the QR code and entering the passkey, ensuring only authorized users can access the data.

This project demonstrates how advanced cryptographic techniques can be applied in practical, accessible tools to protect sensitive information, addressing modern data privacy concerns effectively.
