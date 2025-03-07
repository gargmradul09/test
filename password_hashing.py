import bcrypt

# Hash Password with Higher Work Factor
def hash_password(password):
    salt = bcrypt.gensalt(rounds=14)  # Increase rounds for better security
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

# Verify Password
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

