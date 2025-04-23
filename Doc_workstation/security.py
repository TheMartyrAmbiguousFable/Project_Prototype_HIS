from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import pyotp

# Digital Signature Keys
SIGN_KEY = r"key_sign.pem"
VAL_KEY = r"key_val.pem"

# Symmetric encryption key
FERNET_KEY = b'hU1A6XFxAtzXmOcBEF1Tkd-8LyXlgaOjqM6iBMr8icw='

# 2FA Secret
'''It is not the best practice to hard code the secret in the script, but here we do so for demonstration purposes. 
Normally it should be securely stored somewhere, but that would be of another topic.'''
TOTP_SECRET = "CKOO4DBTNOPH465DB7FIDYWC6VP2U3QI"


# Digital Signature Keys
# Digital signature functions
def signature_sign(data, key=SIGN_KEY):

    with open(key, "rb") as key_file:
        sign_key = serialization.load_pem_private_key(key_file.read(), password=None)
    signature = sign_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def signature_val(data, signature, key=VAL_KEY):

    try:             
        with open(key, "rb") as key_file:
            val_key = serialization.load_pem_public_key(key_file.read())
            val_key.verify(
                        signature,
                        data,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
            result = True
    except Exception as e:
            result = False
    finally:
         return result
    
# 2FA function

def google_auth(gui=False):
    auth_result = False
    totp = pyotp.TOTP(TOTP_SECRET)
    if gui:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        root = tk.Tk()
        root.withdraw()
        user_input = simpledialog.askstring("OTP Verification", 
                                            "Enter the OTP from your Google Authenticator app:")
        root.destroy()
    else:
        user_input = input("\nEnter the OTP from your Google Authenticator app: ").strip()
    if totp.verify(user_input):
        auth_result= True
        print("2FA verification successful!")
    else:
        print("Invalid OTP. Verification failed.")
    return auth_result

# Encryption & Decryption

cipher_suite = Fernet(FERNET_KEY)
def encrypt_message(message):
    """Encrypt message before sending."""
    if isinstance(message, bytes):
        return cipher_suite.encrypt(message)
    else:
        return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(message):
    """Decrypt message on receive."""
    if isinstance(message, bytes):
        return cipher_suite.decrypt(message)
    else:
        return cipher_suite.decrypt(message.encode()).decode()

                
