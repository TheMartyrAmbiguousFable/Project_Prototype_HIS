import socket
from io import BytesIO
import pydicom
import model 
from PIL import Image
import numpy as np
import requests
import getpass
import hashlib

import security

# Security CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
DIGITAL_SIGNATURE = True
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True


def handle_client(client_socket):

    data = b""
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        data += chunk
    print(f"Received {len(data)} bytes from client.")

    # Process the received DICOM file
    try:
        file_like = BytesIO(data)
        ds = pydicom.dcmread(file_like)

        val_result = True
        if DIGITAL_SIGNATURE:
            data_to_val = ds.PixelData
            if (0x0043, 0x1010) in ds:
                signature = ds[(0x0043, 0x1010)].value
                val_result = security.signature_val(data_to_val, signature)
            else:
                val_result = False
                print("Signature not found")

        if val_result:
            pixel_array = ds.pixel_array   
            pixel_data = pixel_array.tobytes()  
            print("pixel data extracted")

            print("Pixel array shape:", pixel_array.shape)
            print("Pixel array dtype:", pixel_array.dtype)

            img = Image.fromarray(pixel_array)

            # Analyze the image using test_model.make_pred
            analysis_result = model.make_pred(img)
            print("analysis result obtained")
        else:
            analysis_result = "Signature validation failed"
    except Exception as e:
        analysis_result = f"Error processing DICOM: {str(e)}"
    
    # Send back the analysis result
    print("sending analysis result back")
    client_socket.sendall(analysis_result.encode("utf-8"))
    print("result sent back")
    client_socket.close()


def start_server(host="0.0.0.0", port=22222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"AI Server listening on {host}:{port}")
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            handle_client(client_socket)
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        server_socket.close()

# Authentication
def authenticate():
    """Performs primary authentication followed by an optional 2FA step."""
    staff_id = input("Enter your Staff ID: ").strip()
    password = getpass.getpass("Enter your Password: ").strip()
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    enc_id, enc_pwd_hash = security.encrypt_message(staff_id), security.encrypt_message(pwd_hash)

    try:
        response = requests.post(
            AUTH_SERVER_URL,
            json={"id": enc_id, "password": enc_pwd_hash},
            timeout=5
        )
        if response.status_code == 200:
            if TWO_FA:
                if not security.google_auth():
                    print("Error: Two-factor authentication failed.")
                    return None
            token = response.json().get("token")
            print("Authentication successful.")
            return token
        else:
            print("Authentication failed:", response.json().get("error", "Unknown error"))
            return None
    except Exception as e:
        print("Error during authentication:", str(e))
        return None

if __name__ == "__main__":
    if authenticate():
        start_server()
