from flask import Flask, render_template, request, jsonify
import requests
import hashlib
import bcrypt
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Configure SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model for Passwords
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(255))

# Create the database tables
with app.app_context():
    db.create_all()

# HIBP API Endpoint
HIBP_API = "https://api.pwnedpasswords.com/range/"

def check_breach(password):
    """Check if a password has been leaked using the HIBP API."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    response = requests.get(HIBP_API + prefix)

    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"⚠️ Password found in {count} breaches!"
        return "✅ Password is safe (not found in breaches)."
    return "❌ HIBP API Error. Try again later."

def check_strength(password):
    """Basic password strength checker (can be improved)."""
    length_score = min(len(password) / 2, 10)  # Score up to 10
    digit_score = sum(c.isdigit() for c in password) * 2
    special_score = sum(not c.isalnum() for c in password) * 3
    total_score = length_score + digit_score + special_score
    return min(total_score, 30)  # Max score capped at 30

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_password():
    data = request.json
    password = data['password']

    strength = check_strength(password)
    breach_result = check_breach(password)

    if "⚠️ Password found" in breach_result:
        return jsonify({'message': breach_result})

    # Hash and store non-breached passwords
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    new_entry = Password(password_hash=hashed_password)
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({'message': f"✅ Password Strength: {strength}/30"})

if __name__ == '__main__':
    app.run(debug=True, port=5500)

