import streamlit as st
import hashlib
import base64
import json
import os
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ---------- Utility Functions ----------

def derive_key(passkey: str, salt: bytes = b'streamlit_salt') -> bytes:
    # PBKDF2-HMAC with SHA-256, 100,000 iterations
    key = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000, dklen=32)
    return base64.urlsafe_b64encode(key)

def load_data():
    if os.path.exists("data.json"):
        with open("data.json", "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f)

# ---------- Session Initialization ----------

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'data_store' not in st.session_state:
    st.session_state.data_store = load_data()

MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 60  # in seconds

# ---------- Authentication System ----------

USER_DB = {
    "alice": "password123",
    "bob": "securepass"
}

def login_page():
    st.title("🔐 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in USER_DB and USER_DB[username] == password:
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.session_state.username = username
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials.")

# ---------- Data Encryption ----------

def encrypt_data(data: str, passkey: str) -> str:
    key = derive_key(passkey)
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(enc_data: str, passkey: str) -> str:
    try:
        key = derive_key(passkey)
        f = Fernet(key)
        return f.decrypt(enc_data.encode()).decode()
    except Exception:
        raise ValueError("Decryption failed.")

# ---------- Pages ----------

def home_page():
    st.title(f"Welcome, {st.session_state.username}")
    choice = st.selectbox("Choose an action", ["Store New Data", "Retrieve Data", "Logout"])
    if choice == "Store New Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
    elif choice == "Logout":
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.success("You’ve been logged out.")

def insert_data_page():
    st.header("📥 Store New Data")
    data = st.text_area("Enter data to store")
    passkey = st.text_input("Enter a passkey (will be used for encryption)", type="password")

    if st.button("Encrypt and Store"):
        if data and passkey:
            encrypted = encrypt_data(data, passkey)
            user_data = st.session_state.data_store.get(st.session_state.username, {})
            hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()
            user_data[hashed_passkey] = encrypted
            st.session_state.data_store[st.session_state.username] = user_data
            save_data(st.session_state.data_store)
            st.success("Data stored securely.")
        else:
            st.warning("Please enter both data and a passkey.")

def retrieve_data_page():
    st.header("🔍 Retrieve Data")
    
    if st.session_state.lockout_time:
        if time.time() < st.session_state.lockout_time:
            st.error(f"Too many attempts. Try again in {int(st.session_state.lockout_time - time.time())} seconds.")
            return
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None

    passkey = st.text_input("Enter your passkey to retrieve data", type="password")

    if st.button("Decrypt Data"):
        hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()
        user_data = st.session_state.data_store.get(st.session_state.username, {})

        if hashed_passkey in user_data:
            try:
                decrypted = decrypt_data(user_data[hashed_passkey], passkey)
                st.success("Decryption successful!")
                st.code(decrypted)
                st.session_state.failed_attempts = 0
            except Exception:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey. Failed attempts: {st.session_state.failed_attempts}")
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Passkey not found. Failed attempts: {st.session_state.failed_attempts}")

        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
            st.session_state.authenticated = False
            st.warning("🔒 Too many failed attempts. You are now logged out and must reauthorize.")

# ---------- App Controller ----------

def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        home_page()

main()
