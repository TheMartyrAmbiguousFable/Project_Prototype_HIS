#!/usr/bin/env python3
import os
import sqlite3
import logging
from datetime import datetime
from io import BytesIO
import threading
import socket
import pydicom
from pydicom import Dataset
from pydicom.uid import SecondaryCaptureImageStorage, ExplicitVRLittleEndian, ImplicitVRLittleEndian
from pynetdicom import AE, evt, debug_logger
from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelGet,
    PatientRootQueryRetrieveInformationModelMove,
    SecondaryCaptureImageStorage,
)
from cryptography.fernet import Fernet
import getpass
import requests
import hashlib

import security

debug_logger()

# Security CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
DIGITAL_SIGNATURE = True
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# PACS CONFIG
PACS_DB = "pacs_database.db"
PACS_STORAGE_DIR = "pacs_storage"
PACS_AE_TITLE = "PACS"
PACS_IP = "0.0.0.0"
PACS_PORT = 11112
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"

os.makedirs(PACS_STORAGE_DIR, exist_ok=True)

# DATABASE INITIALIZATION
def init_pacs_db():
    conn = sqlite3.connect(PACS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS instances (
            PatientID TEXT,
            PatientName TEXT,
            StudyInstanceUID TEXT,
            SOPInstanceUID TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()

init_pacs_db()

# DICOM HANDLERS
def handle_echo(event):
    """Handle C-ECHO request."""
    return 0x0000

def handle_store(event):
    """Handle C-STORE request, encrypt and store DICOM, save metadata."""
    try:
        ds = event.dataset

        val_result = True
        if DIGITAL_SIGNATURE:
            data_to_val = ds.PixelData
            if (0x0043, 0x1010) in ds:
                signature = ds[(0x0043, 0x1010)].value
                val_result = security.signature_val(data_to_val, signature)
            else:
                val_result = False
                logging.error(f"SIGNATURE NOT FOUND")
            
        if val_result:
            ds.file_meta = event.file_meta

            # Extract metadata
            patient_id = str(ds.get("PatientID", ""))
            patient_name = str(ds.get("PatientName", ""))
            study_instance_uid = str(ds.get("StudyInstanceUID", ""))
            sop_instance_uid = str(ds.get("SOPInstanceUID", ""))

            # Save metadata to database
            conn = sqlite3.connect(PACS_DB)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO instances 
                (PatientID, PatientName, StudyInstanceUID, SOPInstanceUID)
                VALUES (?, ?, ?, ?)
            """, (patient_id, patient_name, study_instance_uid, sop_instance_uid))
            conn.commit()
            conn.close()

            with BytesIO() as buffer:
                ds.save_as(buffer, write_like_original=False)
                dicom_bytes = buffer.getvalue()

            encrypted_bytes = security.encrypt_message(dicom_bytes)
            file_path = os.path.join(PACS_STORAGE_DIR, f"{sop_instance_uid}.dcm.enc")
            with open(file_path, "wb") as f:
                f.write(encrypted_bytes)

            return 0x0000
        else:
            logging.error(f"SIGNATURE VALIDATION FAILED")
            return 0xC001 
    except Exception as e:
        logging.error(f"C-STORE failed: {e}")
        return 0xC001 

def handle_find(event):
    """Handle C-FIND request using metadata from database."""
    query_ds = event.identifier
    patient_id = query_ds.get("PatientID", "*")
    conn = sqlite3.connect(PACS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT PatientID, PatientName, StudyInstanceUID, SOPInstanceUID 
        FROM instances 
        WHERE PatientID LIKE ?
    """, (patient_id.replace('*', '%'),))
    results = cursor.fetchall()
    conn.close()

    for row in results:
        match_ds = Dataset()
        match_ds.QueryRetrieveLevel = "PATIENT"
        match_ds.PatientID = row[0]
        match_ds.PatientName = row[1]
        match_ds.StudyInstanceUID = row[2]
        match_ds.SOPInstanceUID = row[3]
        yield (0xFF00, match_ds)
    yield (0x0000, None)

def handle_get(event):
    """Handle C-GET request, decrypt and return DICOM datasets."""
    query_ds = event.identifier
    patient_id = query_ds.get("PatientID", "")

    conn = sqlite3.connect(PACS_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT SOPInstanceUID FROM instances WHERE PatientID = ?", (patient_id,))
    sop_instances = [row[0] for row in cursor.fetchall()]
    conn.close()

    yield len(sop_instances)
    for sop_uid in sop_instances:
        file_path = os.path.join(PACS_STORAGE_DIR, f"{sop_uid}.dcm.enc")
        if not os.path.exists(file_path):
            logging.error(f"Missing DICOM file: {sop_uid}")
            yield (0xC001, None)
            continue
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            if DECRYPTION:
                data = security.decrypt(data)
            ds = pydicom.dcmread(BytesIO(data))
            yield (0xFF00, ds)
        except Exception as e:
            logging.error(f"Failed to retrieve {sop_uid}: {e}")
            yield (0xC001, None)
    yield (0x0000, None)

# Non-DICOM file retrival method
def handle_file_request(conn):
    try:
        file_name = conn.recv(4096)
        if not file_name:
            conn.close()
            return
        if DECRYPTION:
            file_name = security.decrypt_message(file_name).decode()
        logging.info(f"File request for: {file_name}")
        file_path = os.path.join(PACS_STORAGE_DIR, file_name)
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                file_data = f.read()
            conn.sendall(file_data)
        else:
            logging.error(f"Requested file {file_name} not found")
            conn.sendall(b"")
    except Exception as e:
        logging.error(f"Error handling file request: {e}")
    finally:
        conn.close()

def start_file_retrieval_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("0.0.0.0", 22222))
    server_sock.listen(5)
    logging.info("File retrieval server started on port 22222")
    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_file_request, args=(conn,), daemon=True).start()

# START PACS SERVER
def start_pacs_server():
    ae = AE(ae_title=PACS_AE_TITLE)
    ae.supported_contexts.clear()
    ae.add_supported_context(VERIFICATION_SOP_CLASS_UID)
    ae.add_supported_context(SecondaryCaptureImageStorage, ExplicitVRLittleEndian)
    ae.add_supported_context(SecondaryCaptureImageStorage, ImplicitVRLittleEndian)
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelFind)
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelGet)
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelMove)

    handlers = [
        (evt.EVT_C_ECHO, handle_echo),
        (evt.EVT_C_STORE, handle_store),
        (evt.EVT_C_FIND, handle_find),
        (evt.EVT_C_GET, handle_get),
    ]

    ae.start_server((PACS_IP, PACS_PORT), block=True, evt_handlers=handlers)

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
    logging.info("Starting PACS server...")
    if authenticate():
        threading.Thread(target=start_file_retrieval_server, daemon=True).start()
        start_pacs_server()
