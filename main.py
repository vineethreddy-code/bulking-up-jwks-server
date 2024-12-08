# EUID: mv0487
# Name: Vineeth Reddy

from flask import Flask, request, jsonify
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from passlib.hash import argon2
import time

# Initialize Flask app
app = Flask(__name__)

# SQLite database file
database_file = "secure_database.db"
conn = sqlite3.connect(database_file, check_same_thread=False)

# Helper to create tables if not exist
def setup_database():
    create_table_keys_sql = """
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """
    create_table_users_sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """
    create_table_auth_logs_sql = """
    CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """
    conn.execute(create_table_keys_sql)
    conn.execute(create_table_users_sql)
    conn.execute(create_table_auth_logs_sql)
    conn.commit()

setup_database()

# Encryption key helper
def get_encryption_key():
    key = os.environ.get("MY_SECURE_KEY")
    if not key:
        key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        os.environ["MY_SECURE_KEY"] = key
    return base64.urlsafe_b64decode(key)

# Encrypt private key
def encrypt_private_key(key, expiration_time, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(b'\0' * 16), backend=default_backend())
    cipher_text = cipher.encryptor().update(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (cipher_text, int(expiration_time.timestamp())))
    conn.commit()

# Generate RSA keys for testing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

encrypt_private_key(private_key, datetime.datetime.utcnow() + datetime.timedelta(hours=1), get_encryption_key())
encrypt_private_key(expired_key, datetime.datetime.utcnow() - datetime.timedelta(hours=1), get_encryption_key())

@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Invalid request"}), 400

    # Simulate JWT creation for the sake of the example
    token_payload = {
        "user": data['username'],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(token_payload, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm="RS256")

    return jsonify({"token": token})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Invalid request"}), 400

    hashed_password = argon2.hash(data['password'])
    try:
        conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                     (data['username'], hashed_password, data.get('email')))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 409

    return jsonify({"message": "User registered successfully"}), 201

if __name__ == "__main__":
    app.run(port=8080, debug=True)
