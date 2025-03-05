import bcrypt

# Hash Password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Verify Password
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)

# Run the script
if __name__ == "__main__":
    password = input("Enter a password to hash: ")
    
    # Hash the password
    hashed_password = hash_password(password)
    print(f"\n🔒 Hashed Password: {hashed_password.decode()}")

    # Verify password
    check = input("\nEnter the password again to verify: ")
    if verify_password(check, hashed_password):
        print("✅ Password match!")
    else:
        print("❌ Password does NOT match!")

