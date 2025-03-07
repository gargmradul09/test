import hashlib
import requests
import secrets
import string

def check_breach(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    first5, tail = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}", timeout=5)
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if tail == hash_suffix:
                return {
                    "breached": True,
                    "message": f"⚠️ Password found in {count} breaches!",
                    "new_password": generate_secure_password()
                }
        return {"breached": False, "message": "✅ Password is safe."}
    
    except requests.exceptions.RequestException:
        return {"breached": None, "message": "❌ Error: Unable to check breach, try again later."}

def generate_secure_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(16))

