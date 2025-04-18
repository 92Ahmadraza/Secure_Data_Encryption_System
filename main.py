import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

# Helper to derive Fernet key from passkey
def derive_key(passkey: str) -> bytes:
    # SHA-256 hash → 32-byte key, then base64 encode for Fernet
    return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}  # key: encrypted data
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'max_attempts' not in st.session_state:
    st.session_state.max_attempts = 3

# Login page (forced after max failed attempts)
def login():
    st.title("🔐 Secure Data App - Login")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")
    if st.button("Login"):
        if username == "admin" and password == "password":
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("Login successful!")
        else:
            st.error("Invalid credentials.")

# Main app
def secure_data_app():
    st.title("🔐 In-Memory Secure Data Storage")

    menu = st.sidebar.radio("Choose an action", ["Store Data", "Retrieve Data", "Logout"])

    if menu == "Store Data":
        passkey = st.text_input("Enter a passkey", type="password")
        data = st.text_area("Data to encrypt and store")
        if st.button("Encrypt & Store"):
            if passkey and data:
                key = derive_key(passkey)
                f = Fernet(key)
                encrypted = f.encrypt(data.encode())
                st.session_state.data_store[passkey] = encrypted
                st.success("Data stored securely!")
            else:
                st.warning("Please enter both a passkey and some data.")

    elif menu == "Retrieve Data":
        passkey = st.text_input("Enter your passkey to retrieve data", type="password")
        if st.button("Decrypt & Retrieve"):
            if passkey in st.session_state.data_store:
                try:
                    key = derive_key(passkey)
                    f = Fernet(key)
                    decrypted = f.decrypt(st.session_state.data_store[passkey]).decode()
                    st.success("Data successfully decrypted:")
                    st.code(decrypted)
                    st.session_state.failed_attempts = 0  # reset
                except Exception:
                    st.session_state.failed_attempts += 1
                    st.error("Incorrect passkey or decryption error.")
            else:
                st.session_state.failed_attempts += 1
                st.error("Passkey not found.")

            if st.session_state.failed_attempts >= st.session_state.max_attempts:
                st.error("Too many failed attempts. You must reauthorize.")
                st.session_state.authenticated = False

    elif menu == "Logout":
        st.session_state.authenticated = False
        st.success("Logged out successfully.")

# App logic
if not st.session_state.authenticated:
    login()
else:
    secure_data_app()
