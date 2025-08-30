# generate_key.py
from cryptography.fernet import Fernet

# یک کلید جدید و امن تولید می‌کند
key = Fernet.generate_key()

print("کلید جدید شما:")
print(key.decode())