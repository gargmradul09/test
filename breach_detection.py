import hashlib
import requests

def check_breach(password):
    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    
    # Split hash: First 5 characters for query, remaining as tail
    first5, tail = sha1_hash[:5], sha1_hash[5:]

    # Send request to HIBP API
    response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")

    # Check if tail exists in response
    if tail in response.text:
        return True  # Password breached
    return False  # Password safe

# Run the script
if __name__ == "__main__":
    password = input("Enter your password: ")
    if check_breach(password):
        print("⚠️ This password has been breached! Use a different one.")
    else:
        print("✅ This password is safe.")

