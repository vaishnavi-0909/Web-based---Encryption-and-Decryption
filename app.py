import streamlit as st
from encryption_module import aes_encrypt, derive_key_from_passkey, generate_qr_code, aes_decrypt
from decryption_process import read_qr_code
import tempfile
import base64

st.title("Secure File Encryption and Decryption")
st.write("Encrypt and decrypt text securely using AES encryption and QR code-based multi-factor authentication.")

# Add options for encryption and decryption
option = st.selectbox("Choose an action", ["Encrypt", "Decrypt"])

if option == "Encrypt":
    st.header("File Encryption")
    plain_text = st.text_area("Enter the text you want to encrypt:")
    passkey = st.text_input("Enter a passkey (10-20 characters, must include letters, digits, and special characters):",
                            type="password")

    if st.button("Encrypt Text"):
        if plain_text and len(passkey) >= 10 and len(passkey) <= 20:
            try:
                # Derive a secure AES key from the passkey
                aes_key = derive_key_from_passkey(passkey)

                # Generate an XOR key by XORing the AES key with the passkey
                passkey_bytes = passkey.encode()
                xor_key = bytes(a ^ b for a, b in zip(aes_key, passkey_bytes.ljust(len(aes_key), b'\0')))

                # Encrypt the plain text
                cipher_text = aes_encrypt(plain_text, aes_key)

                # Generate QR codes for XOR key and cipher text
                xor_key_qr_buffer = generate_qr_code(base64.b64encode(xor_key).decode(), return_buffer=True)
                text_qr_buffer = generate_qr_code(cipher_text, return_buffer=True)
                # Save QR codes in session state
                st.session_state.xor_key_qr_buffer = xor_key_qr_buffer
                st.session_state.text_qr_buffer = text_qr_buffer
                # Display success message and allow downloads
                st.success("Encryption successful! Please download the QR codes below.")

            except ValueError as e:
                st.error(f"Error: {str(e)}")
        else:
            st.error("Please enter valid input text and a strong passkey.")

    # Provide download buttons only if QR codes are generated
    if 'xor_key_qr_buffer' in st.session_state and 'text_qr_buffer' in st.session_state:
        st.download_button(
            label="Download Key QR Code",
            data=st.session_state.xor_key_qr_buffer.getvalue(),
            file_name="encryption_key_qr.png"
        )
        st.download_button(
            label="Download Encrypted Text QR Code",
            data=st.session_state.text_qr_buffer.getvalue(),
            file_name="encrypted_text_qr.png"
        )


if option == "Decrypt":
    st.header("File Decryption")
    key_qr = st.file_uploader("Upload the QR code image for the XOR key", type=["png", "jpg"])
    text_qr = st.file_uploader("Upload the QR code image for the encrypted text", type=["png", "jpg"])
    passkey = st.text_input(
        "Enter the passkey used during encryption:",
        type="password"
    )

    if st.button("Decrypt Text"):
        if key_qr and text_qr and passkey:
            try:
                # Save uploaded QR files to temporary paths
                with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as key_temp:
                    key_temp.write(key_qr.read())
                    key_qr_path = key_temp.name

                with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as text_temp:
                    text_temp.write(text_qr.read())
                    text_qr_path = text_temp.name

                # Read data from QR codes
                xor_key = base64.b64decode(read_qr_code(key_qr_path))
                cipher_text = read_qr_code(text_qr_path)

                # Reconstruct AES key using XOR of passkey and XOR key
                passkey_bytes = passkey.encode()
                aes_key = bytes(a ^ b for a, b in zip(xor_key, passkey_bytes.ljust(len(xor_key), b'\0')))

                # Decrypt the cipher text
                decrypted_text = aes_decrypt(cipher_text, aes_key)

                # Display the decrypted text
                st.success("Decryption successful! Here is the decrypted text:")
                st.text(decrypted_text)

            except ValueError as e:
                st.error(f"Decryption failed: {str(e)}")
        else:
            st.error("Please upload both QR codes and enter the passkey.")
