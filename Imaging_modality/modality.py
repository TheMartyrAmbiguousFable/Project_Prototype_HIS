#!/usr/bin/env python3
import time
import threading
import logging
import socket
import os
import random
import glob
from datetime import datetime
import tempfile
from queue import Queue
from cryptography.fernet import Fernet
import uuid
import pydicom
from pydicom import Dataset
from pydicom.uid import generate_uid, JPEGBaseline8Bit, SecondaryCaptureImageStorage, ExplicitVRLittleEndian, ImplicitVRLittleEndian 
from pynetdicom import AE, evt
from hl7apy.core import Message
from hl7apy import parser
from PIL import Image
import numpy as np
from io import BytesIO
import getpass
import requests
import hashlib

import security

# Security Config
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
DIGITAL_SIGNATURE = True
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# NETWORK & Modality CONFIG
MWL_FIND_UID = '1.2.840.10008.5.1.4.31'
PACS_CONFIG = {
    "ae_title":"PACS",
    "ip": "172.31.7.195",
    "port": 11112
}
RIS_MWL_CONFIG = {
    "ae_title": "RIS_MWL",
    "ip": "172.31.45.74", 
    "port": 6000
}
HL7_RIS_CONFIG = {
    "ip": "172.31.45.74", 
    "port": 5001
}
IMAGES_DIR = "/home/ubuntu/images"
SUBDIRS = ["normal", "glioma", "meningioma", "pituitary"]

# Global state
current_worklist = []
current_patient = None
exam_in_progress = False
dicom_queue = Queue()

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


# DICOM MWL FUNCTIONS
def fetch_worklist():
    """Retrieve worklist from RIS using DICOM MWL C-FIND"""
    ae = AE(ae_title="MODALITY_AE")
    ae.add_requested_context(MWL_FIND_UID)
    
    try:
        assoc = ae.associate(
            RIS_MWL_CONFIG["ip"], 
            RIS_MWL_CONFIG["port"],
            ae_title=RIS_MWL_CONFIG["ae_title"]
        )
        
        if not assoc.is_established:
            return []

        ds = Dataset()
        ds.QueryRetrieveLevel = "PATIENT"
        ds.PatientName = "*"
        ds.PatientID = "*"
        ds.ScheduledProcedureStepSequence = [Dataset()]
        ds.ScheduledProcedureStepSequence[0].ScheduledProcedureStepStartDate = "*"

        worklist = []
        responses = assoc.send_c_find(ds, MWL_FIND_UID)
        for (status, dataset) in responses:
            if status.Status in [0xFF00, 0xFF01] and dataset:
                worklist.append(dataset)
        
        assoc.release()
        return worklist
    
    except Exception as e:
        logging.error(f"DICOM Association error: {e}")
        return []

# HL7 FUNCTIONS
def construct_hl7_oru(patient_ds):
    """Create ORU^R01 message for exam completion"""
    msg = Message("ORU_R01")
    msg.msh.msh_3 = "MODALITY"
    msg.msh.msh_5 = "RIS"
    msg.msh.msh_9 = "ORU^R01"
    msg.msh.msh_10 = str(uuid.uuid4())
    msg.msh.msh_12 = "2.5"

    pid = msg.add_segment("PID")
    pid.pid_3 = str(patient_ds.PatientID)
    pid.pid_5 = str(patient_ds.PatientName)
    pid.pid_7 = str(patient_ds.PatientBirthDate)

    obr = msg.add_segment("OBR")
    obr.obr_4 = "EXAM_COMPLETED"

    return msg.to_er7().replace("\n", "\r")

def send_hl7_message(message):
    """Send encrypted HL7 message to RIS"""
    try:
        if ENCRYPTION:
            message = security.encrypt_message(message.encode()).decode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((HL7_RIS_CONFIG["ip"], HL7_RIS_CONFIG["port"]))
            s.sendall(message.encode())
            response = s.recv(4096).decode()
            if DECRYPTION:
                response = security.decrypt_message(response.encode()).decode()
            if "AA" in response:
                logging.info("HL7 ACK received")
            else:
                logging.error(f"HL7 Error: {response}")
    except Exception as e:
        logging.error(f"HL7 Send failed: {e}")

# IMAGE PROCESSING
def create_dicom(patient_ds, image_path):
    """Create DICOM file from JPEG using patient data from MWL"""
    file_meta = pydicom.Dataset()
    file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = pydicom.Dataset()
    ds.file_meta = file_meta
    ds.PatientID = patient_ds.PatientID
    ds.PatientName = patient_ds.PatientName
    ds.PatientBirthDate = patient_ds.PatientBirthDate
    ds.StudyDate = datetime.now().strftime("%Y%m%d")
    ds.StudyTime = datetime.now().strftime("%H%M%S")
    ds.Modality = "OT"
    ds.SOPClassUID = SecondaryCaptureImageStorage
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = patient_ds.StudyInstanceUID
    ds.SeriesInstanceUID = pydicom.uid.generate_uid()
    ds.is_implicit_VR = False
    ds.is_little_endian = True

    # Use Pillow to open image and NumPy to get uncompressed pixel data
    img = Image.open(image_path)
    pixel_array = np.array(img)
    ds.PixelData = pixel_array.tobytes()

    ds.Rows = pixel_array.shape[0]
    ds.Columns = pixel_array.shape[1]
    if pixel_array.ndim == 3:
        ds.SamplesPerPixel = pixel_array.shape[2]
        ds.PhotometricInterpretation = "RGB"
        ds.PlanarConfiguration = 0
    else:
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = pixel_array.dtype.itemsize * 8
    ds.BitsStored = ds.BitsAllocated
    ds.HighBit = ds.BitsStored - 1
    ds.PixelRepresentation = 0

    if DIGITAL_SIGNATURE:
        signature = security.signature_sign(ds.PixelData)
        ds.add_new((0x0043, 0x0010), 'LO', 'SIGNATURE')
        ds.add_new((0x0043, 0x1010), 'OB', signature)

    temp_dir = tempfile.gettempdir()
    dicom_path = os.path.join(temp_dir, f"{patient_ds.PatientID}.dcm")
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    ds.save_as(dicom_path, write_like_original=False)
    
    with BytesIO() as buffer:
        ds.save_as(buffer, write_like_original=False)
        dicom_bytes = buffer.getvalue()
    return dicom_bytes

# EXAM WORKFLOW
def start_exam(patient_ds):
    global exam_in_progress
    exam_in_progress = True
    
    # Select random image
    chosen_subdir = random.choice(SUBDIRS)
    subdir_path = os.path.join(IMAGES_DIR, chosen_subdir)
    image_files = glob.glob(os.path.join(subdir_path, "*.jpg"))
    
    if not image_files:
        logging.error("No images available")
        return

    chosen_image = random.choice(image_files)
    logging.info(f"Using image: {chosen_image}")
    
    hl7_msg = construct_hl7_oru(patient_ds)
    send_hl7_message(hl7_msg)
    
    dicom_bytes = create_dicom(patient_ds, chosen_image)
    try:
        send_dicom_to_pacs(dicom_bytes)
        logging.info("DICOM sent to PACS successfully")
    except Exception as e:
        if ENCRYPTION:
            dicom_bytes = security.encrypt_message(dicom_bytes)
        dicom_queue.put(dicom_bytes)
        logging.error(f"PACS send failed: {e}")        
    finally:
        exam_in_progress = False


def send_dicom_to_pacs(dicom_bytes):
    """Send DICOM to PACS using C-STORE."""
    ae = AE(ae_title="MODALITY")
    ae.add_requested_context(SecondaryCaptureImageStorage, ExplicitVRLittleEndian)
    ae.add_requested_context(SecondaryCaptureImageStorage, ImplicitVRLittleEndian)
    try:
        assoc = ae.associate(PACS_CONFIG["ip"], PACS_CONFIG["port"], ae_title=PACS_CONFIG["ae_title"])
        if assoc.is_established:
            ds = pydicom.dcmread(BytesIO(dicom_bytes))
            status = assoc.send_c_store(ds)
            if status.Status != 0x0000:
                raise Exception(f"C-STORE failed with status 0x{status.Status:04X}")
        else:
            raise Exception("Association rejected")
    except Exception as e:
        raise e
    finally:
        if assoc.is_established:
            assoc.release()


# Main Loop
def worklist_monitor():
    global current_patient
    while True:
        worklist = fetch_worklist()
        if worklist:
            new_patient = worklist[0]
            if current_patient != new_patient:
                current_patient = new_patient
                print(f"\nPatient: {new_patient.PatientName}")
                print(f"DOB: {new_patient.PatientBirthDate}")
                print(f"PID: {new_patient.PatientID}")
                print("Press S to start examination:")
        time.sleep(10)

def input_handler():
    while True:
        if current_patient and not exam_in_progress:
            user_input = input().strip().upper()
            if user_input == 'S':
                logging.info("Starting exam...")
                threading.Thread(target=start_exam, args=(current_patient,)).start()

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
    logging.info("Modality service starting...")
    
    if authenticate():
        monitor_thread = threading.Thread(target=worklist_monitor, daemon=True)
        monitor_thread.start()
        
        input_thread = threading.Thread(target=input_handler, daemon=True)
        input_thread.start()
        
        while True:
            time.sleep(1)
