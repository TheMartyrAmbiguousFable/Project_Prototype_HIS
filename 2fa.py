import pyotp
import qrcode
import time

def setup_google_authenticator():
    secret = pyotp.random_base32()
    print("Your secret key:", secret, ", use it to replace the secret key on security.py")
    
    totp = pyotp.TOTP(secret)
    
    # name and issuer_name can be replaced
    provisioning_uri = totp.provisioning_uri(name="zhisongchen91@outlook.com", issuer_name="Hospital_2FA")
    print("\nProvisioning URI:", provisioning_uri)
    
    qr = qrcode.make(provisioning_uri)
    qr_filename = "google_auth_qr.png"
    qr.save(qr_filename)
    qr.show()
    print(f"\nA QR code has been saved as {qr_filename}.")
    print("Scan this QR code with your Google Authenticator app to set up the account.")

if __name__ == "__main__":
    setup_google_authenticator()
