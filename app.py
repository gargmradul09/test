from flask import Flask, request, jsonify, render_template
import sqlite3
import hashlib
import os
import secrets
import string
import requests
import bcrypt
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, site TEXT, hashed_password TEXT)")
    conn.commit()
    conn.close()

init_db()

def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return {"breached": True, "message": f"⚠️ Password found in {count} breaches!", "new_password": generate_secure_password()}
        return {"breached": False, "message": "✅ Password is safe."}
    
    return {"breached": None, "message": "❌ HIBP API Error. Try again later."}

def generate_secure_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(16))

def check_strength(password):
    length_score = min(len(password) / 2, 10)
    digit_score = sum(c.isdigit() for c in password) * 2
    special_score = sum(not c.isalnum() for c in password) * 3
    total_score = length_score + digit_score + special_score
    return min(total_score, 30)

@app.route("/")
def index():
    return render_template("index.html")  # No login required anymore

@app.route("/store_password", methods=["POST"])
def store_password():
    data = request.json
    site = data.get("site")
    password = data.get("password")

    if not site or not password:
        return jsonify({"error": "Site and password are required!"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (site, hashed_password) VALUES (?, ?)", (site, hashed_password))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Password stored securely!"})

@app.route("/check_breach", methods=["POST"])
def check_breach():
    data = request.json
    password = data.get("password")

    if not password:
        return jsonify({"error": "Password is required!"}), 400

    breach_result = check_password_breach(password)
    return jsonify(breach_result)

@app.route("/analyze", methods=["POST"])
def analyze_password():
    data = request.json
    password = data.get('password')

    if not password:
        return jsonify({"error": "Password is required!"}), 400

    strength = check_strength(password)
    breach_result = check_password_breach(password)

    if breach_result["breached"]:
        return jsonify({'message': breach_result["message"], 'suggestion': breach_result["new_password"]})

    return jsonify({'message': f"✅ Password Strength: {strength}/30"})

if __name__ == "__main__":
    app.run(debug=True)

