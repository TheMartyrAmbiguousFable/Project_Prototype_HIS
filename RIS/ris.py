#!/usr/bin/env python3
import os
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import uuid
import time
import socket
import logging
import datetime
from io import BytesIO

import pydicom
from pydicom.uid import generate_uid, ExplicitVRLittleEndian, ImplicitVRLittleEndian
from pydicom.pixel_data_handlers.util import apply_voi_lut
from hl7apy.parser import parse_message
from hl7apy.core import Message
from pynetdicom import AE, evt, debug_logger
from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind,
    PatientRootQueryRetrieveInformationModelMove,
    SecondaryCaptureImageStorage,
)
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
import numpy
import hashlib

import security

# debug_logger()

# Security CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
DIGITAL_SIGNATURE = True
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# NETWORK & DB CONFIG
orders_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Orders")
os.makedirs(orders_dir, exist_ok=True)
RIS_DB = os.path.join(orders_dir, "ris_orders.db")

MODALITY_WORKLIST_FIND_UID = '1.2.840.10008.5.1.4.31'

IPS = {
    'EMR': {'ip': "172.31.25.176", 'port': 2575},
    'RIS': {'ip': "0.0.0.0", 'port': 5001},
    'PACS': {'ip': "172.31.7.195", 'port': 11112},
    'MODALITY': {'ip': "172.31.5.12", 'port': 5002}
}

PACS_AE_TITLE = "PACS"
RIS_AE_TITLE = "RIS"
RIS_MWL_AE_TITLE = "RIS_MWL"

# DATABASE INITIALIZATION
def init_ris_db():
    conn = sqlite3.connect(RIS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radiology_orders (
            order_number INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT,
            name TEXT,
            dob TEXT,
            exam_type TEXT,
            status TEXT DEFAULT 'ordered'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_queue_ris (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            target_system TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_ris_db()

# HL7 ACK BUILDER
def create_ack(msg, code, text=""):
    ack = Message("ACK")
    ack.msh.msh_3 = "RIS"
    if msg and hasattr(msg, 'msh'):
        ack.msh.msh_5 = msg.msh.msh_3.value
        ack.msh.msh_10 = msg.msh.msh_10.value
    else:
        ack.msh.msh_5 = "UNK"
        ack.msh.msh_10 = str(uuid.uuid4())
    ack.msh.msh_12 = "2.5"
    ack.msa.msa_1 = code
    ack.msa.msa_3 = text
    return ack.to_er7().replace("\n", "\r")

# DICOM QUERY FUNCTIONS
def query_all_exams_for_patient(patient_id):

    ae = AE(ae_title=RIS_AE_TITLE)
    ae.add_supported_context(MODALITY_WORKLIST_FIND_UID)
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    assoc = ae.associate(IPS["PACS"]["ip"], IPS["PACS"]["port"], ae_title=PACS_AE_TITLE)
    if not assoc.is_established:
        messagebox.showerror("DICOM Association Failed", "Unable to establish association with PACS for query.")
        return []
    
    ds = pydicom.Dataset()
    ds.QueryRetrieveLevel = "PATIENT"
    ds.PatientID = patient_id
    exam_records = []
    responses = assoc.send_c_find(ds, PatientRootQueryRetrieveInformationModelFind)
    for (status, identifier) in responses:
        if status and identifier:
            exam_records.append(identifier)
    assoc.release()
    return exam_records

# Non-DICOM file retrival
def retrieve_file_from_pacs(instance_uid):
    """
    Build the file name string using the InstanceUID, encrypt it, and send it to the PACS file retrieval server on port 22222.
    Then receive the file, decrypt its content, and return the DICOM dataset.
    This is not a standard way of retriving DICOM files and is a temporary solution for an error occurred when using C-GET
    """
    file_name = f"{instance_uid}.dcm.enc"
    if ENCRYPTION:
        file_name = security.encrypt_message(file_name.encode())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((IPS["PACS"]["ip"], 22222))
        s.sendall(file_name)
        file_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            file_data += chunk
        s.close()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to retrieve file: {e}")
        return None

    if not file_data:
        messagebox.showerror("Retrieval Error", "File not found on PACS.")
        return None

    try:
        if DECRYPTION:
            file_data = security.decrypt_message(file_data)
        ds = pydicom.dcmread(BytesIO(file_data))
        return ds
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt file: {e}")
        return None

def extract_image_from_dicom(ds):
    try:
        arr = apply_voi_lut(ds.pixel_array, ds)
        arr = arr - arr.min()
        if arr.max() > 0:
            arr = (arr / arr.max() * 255).astype('uint8')
        img = Image.fromarray(arr)
        return img
    except Exception as e:
        messagebox.showerror("Image Extraction Error", f"Failed to extract image: {e}")
        return None

# DICOM RECEIVER
def handle_mwl_find(event):
    logging.info(f"Received MWL query: {event.identifier}")
    conn = sqlite3.connect(RIS_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT patient_id, name, dob, exam_type FROM radiology_orders WHERE status='ordered'")
    rows = cursor.fetchall()
    conn.close()
    for row in rows:
        ds = pydicom.Dataset()
        ds.PatientID = row[0]
        ds.PatientName = row[1]
        ds.PatientBirthDate = row[2]
        ds.ScheduledProcedureStepDescription = row[3]
        ds.ScheduledProcedureStepStartDate = datetime.datetime.now().strftime("%Y%m%d")
        ds.StudyInstanceUID = generate_uid()
        yield (0xFF00, ds)
    yield (0x0000, None)

def start_mwl_server():
    ae = AE(ae_title=RIS_MWL_AE_TITLE)
    ae.add_supported_context(MODALITY_WORKLIST_FIND_UID)
    handlers = [(evt.EVT_C_FIND, handle_mwl_find)]
    logging.info("RIS MWL Server starting on port 6000 (for modality queries)")
    ae.start_server(("0.0.0.0", 6000), block=True, evt_handlers=handlers)

# HL7 LISTENER
class HL7ListenerRIS(threading.Thread):
    def __init__(self, listen_ip=IPS["RIS"]["ip"], listen_port=IPS["RIS"]["port"]):
        super().__init__(daemon=True)
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.listen_ip, self.listen_port))
        self.sock.listen(5)
        logging.info(f"RIS HL7 Listener running on {self.listen_ip}:{self.listen_port}")

    def run(self):
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()

    def handle_connection(self, conn):
        try:
            data = conn.recv(4096).decode()
            if not data:
                conn.close()
                return
            if DECRYPTION:
                data = security.decrypt_message(data)
            logging.info("RIS Received HL7 message:")
            logging.info(data)
            ack = self.process_message(data)
            if ENCRYPTION:
                ack = security.encrypt_message(ack)
            conn.sendall(ack.encode())
        except Exception as e:
            logging.error(f"Error in RIS HL7Listener: {e}")
            try:
                if ENCRYPTION:
                    conn.sendall(security.encrypt_message(create_ack(None, "AR", str(e))).encode())
                else:
                    conn.sendall(create_ack(None, "AR", str(e)).encode())
            except:
                pass
        finally:
            conn.close()

    def process_message(self, data):
        try:
            msg = parse_message(data)
        except Exception as e:
            return create_ack(None, "AE", "Invalid HL7 message")
        if not hasattr(msg, 'msh'):
            return create_ack(None, "AE", "Missing MSH segment")
        if msg.msh.msh_12.value != "2.5":
            return create_ack(msg, "AE", "Unsupported HL7 version")
        message_type = msg.msh.msh_9.value
        if message_type.startswith("ORM"):
            msg = parse_message(data, find_groups=False)
            return self.handle_order(msg)
        elif message_type.startswith("ORU"):
            msg = parse_message(data, find_groups=False)
            return self.handle_result(msg)
        elif message_type.startswith("QRY"):
            msg = parse_message(data, find_groups=False)
            return self.handle_query(msg)
        else:
            return create_ack(msg, "AE", "Unsupported message type")

    def handle_order(self, msg):
        try:
            pid = next(seg for seg in msg.children if seg.name == "PID")
            patient_id = pid.pid_3.value
            name = pid.pid_5.value
            dob = pid.pid_7.value
            obr = next(seg for seg in msg.children if seg.name == "OBR")
            exam_type = obr.obr_4.value[4:7]
        except Exception as e:
            return create_ack(msg, "AE", f"Order parsing failed: {e}")
        try:
            conn = sqlite3.connect(RIS_DB)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO radiology_orders (patient_id, name, dob, exam_type, status)
                VALUES (?, ?, ?, ?, 'ordered')
            """, (patient_id, name, dob, exam_type))
            conn.commit()
            conn.close()
            logging.info(f"Inserted order for patient {patient_id}")
        except Exception as e:
            return create_ack(msg, "AE", f"Database error: {e}")
        return create_ack(msg, "AA")

    def handle_result(self, msg):
        try:
            pid = next(seg for seg in msg.children if seg.name == "PID")
            patient_id = pid.pid_3.value
        except Exception as e:
            return create_ack(msg, "AE", f"Result parsing failed: {e}")
        try:
            conn = sqlite3.connect(RIS_DB)
            cursor = conn.cursor()
            cursor.execute("UPDATE radiology_orders SET status = 'completed' WHERE patient_id=?", (patient_id,))
            conn.commit()
            conn.close()
            logging.info(f"Updated order status to completed for patient {patient_id}")
        except Exception as e:
            return create_ack(msg, "AE", f"Database error: {e}")
        return create_ack(msg, "AA")

    def handle_query(self, msg):
        return create_ack(msg, "AA", "Query functionality not implemented")

# RETRY THREAD
def forward_hl7_message(target_system, hl7_text):
    try:
        target_ip = IPS[target_system]["ip"]
        target_port = IPS[target_system]["port"]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, target_port))
            if ENCRYPTION:
                hl7_text = security.encrypt_message(hl7_text)
            s.sendall(hl7_text.encode())
            response = s.recv(4096).decode()
            if DECRYPTION:
                return security.decrypt_message(response)
            else:
                return response
    except Exception as e:
        logging.error(f"Forward HL7 message failed: {e}")
        return None

class RetryQueueThreadRIS(threading.Thread):
    def __init__(self, interval=60):
        super().__init__(daemon=True)
        self.interval = interval
    def run(self):
        while True:
            time.sleep(self.interval)
            self.retry_messages()
    def retry_messages(self):
        conn = sqlite3.connect(RIS_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT id, message, target_system FROM message_queue_ris")
        rows = cursor.fetchall()
        for row in rows:
            msg_id, message_text, target_system = row
            response = forward_hl7_message(target_system, message_text)
            if response and "AA" in response:
                cursor.execute("DELETE FROM message_queue_ris WHERE id=?", (msg_id,))
                logging.info(f"Successfully resent queued HL7 message id {msg_id}")
            else:
                cursor.execute("UPDATE message_queue_ris SET attempts = attempts + 1 WHERE id=?", (msg_id,))
                logging.info(f"Retry failed for HL7 message id {msg_id}")
        conn.commit()
        conn.close()

# GUI
class MainAppRIS:
    def __init__(self, token):
        self.token = token
        self.root = tk.Tk()
        self.root.title("RIS Workstation")
        self.root.geometry("800x600")
        self.setup_ui()
        self.root.mainloop()
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="View Orders", command=self.view_orders).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="View Exams", command=self.view_exams).pack(side=tk.LEFT, padx=10)
    def view_orders(self):
        window = tk.Toplevel(self.root)
        window.title("Radiology Orders")
        window.geometry("700x400")
        columns = ("Order #", "Patient ID", "Name", "DOB", "Exam Type", "Status")
        tree = ttk.Treeview(window, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor="center")
        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        conn = sqlite3.connect(RIS_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT order_number, patient_id, name, dob, exam_type, status FROM radiology_orders")
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            try:
                dob_str = row[3] if row[3] else row[3]
                dob_display = dob_str[:4] + '-' + dob_str[4:6] + '-' + dob_str[6:]
            except Exception:
                dob_display = row[3]
            tree.insert("", "end", values=(row[0], row[1], row[2], dob_display, row[4], row[5]))
        menu = tk.Menu(window, tearoff=0)
        menu.add_command(label="Remove Patient", command=lambda: remove_selected())
        def on_right_click(event):
            iid = tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid)
                menu.tk_popup(event.x_root, event.y_root)
        tree.bind("<Button-3>", on_right_click)
        def remove_selected():
            selected = tree.selection()
            if not selected:
                return
            order_number = tree.item(selected[0])["values"][0]
            if messagebox.askyesno("Confirm", f"Remove order #{order_number}?"):
                conn = sqlite3.connect(RIS_DB)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM radiology_orders WHERE order_number=?", (order_number,))
                conn.commit()
                conn.close()
                tree.delete(selected[0])
                messagebox.showinfo("Removed", f"Order #{order_number} removed.")

    def view_exams(self):
        window = tk.Toplevel(self.root)
        window.title("Exam Records for Patient")
        window.geometry("800x400")
        
        input_frame = ttk.Frame(window, padding=10)
        input_frame.pack(fill=tk.X)
        ttk.Label(input_frame, text="Enter Patient ID:").pack(side=tk.LEFT, padx=5)
        patient_id_entry = ttk.Entry(input_frame)
        patient_id_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Retrieve Exams", command=lambda: retrieve_exams()).pack(side=tk.LEFT, padx=5)
        
        columns = ("PatientID", "PatientName", "PatientBirthDate", "InstanceUID")
        tree = ttk.Treeview(window, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor="center")
        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        ttk.Button(window, text="View Selected Image", command=lambda: self.view_selected_exam_image(tree, window)).pack(pady=5)
        
        def retrieve_exams():
            patient_id = patient_id_entry.get().strip()
            if not patient_id:
                messagebox.showerror("Input Error", "Please enter a Patient ID.")
                return
            exam_records = query_all_exams_for_patient(patient_id)
            if not exam_records:
                messagebox.showinfo("No Results", "No exam records found for this patient.")
                return
            for row in tree.get_children():
                tree.delete(row)
            for ds in exam_records:
                tree.insert("", "end", values=(
                    ds.get("PatientID", "N/A"),
                    ds.get("PatientName", "N/A"),
                    ds.get("PatientBirthDate", "N/A"),
                    ds.get("SOPInstanceUID", "N/A"),
                ))

    def view_selected_exam_image(self, tree, parent_window):
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Selection Error", "Please select an exam record to view.")
            return
        item = tree.item(selected[0])
        values = item["values"]
        patient_id = values[0]
        sop_instance_uid = values[3] 

        ds = retrieve_file_from_pacs(sop_instance_uid)
        if ds is None:
            return
        
        val_result = True
        if DIGITAL_SIGNATURE:
            data_to_val = ds.PixelData
            if (0x0043, 0x1010) in ds:
                signature = ds[(0x0043, 0x1010)].value
                val_result = security.signature_val(data_to_val, signature)
            else:
                val_result = False
                messagebox.showerror("Signature not found")
        if val_result:
            img = extract_image_from_dicom(ds)
            if img:
                img_window = tk.Toplevel(parent_window)
                img_window.title(f"Image for Instance {sop_instance_uid}")
                photo = ImageTk.PhotoImage(img)
                label = ttk.Label(img_window, image=photo)
                label.image = photo
                label.pack()
        else:
            messagebox.showerror("Signature validation failed")

# AUTHENTICATION
class AuthWindowGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RIS Workstation - Authentication")
        self.root.geometry("300x200")
        self.setup_ui()
    def setup_ui(self):
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Staff ID:").grid(row=0, column=0, sticky="w", pady=5)
        self.staff_id_entry = ttk.Entry(frame)
        self.staff_id_entry.grid(row=0, column=1, pady=5)
        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)
        ttk.Button(frame, text="Login", command=self.authenticate).grid(row=2, column=0, columnspan=2, pady=15)
    def authenticate(self):
        staff_id = self.staff_id_entry.get().strip()
        password = self.password_entry.get().strip()
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
                    if not security.google_auth(gui=True):
                        messagebox.showerror("Error", "Two-factor authentication failed.")
                        return
                self.token = response.json().get("token")
                self.root.destroy()
                MainAppRIS(self.token)
            else:
                messagebox.showerror("Authentication Error", response.json().get("error", "Authentication failed"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

# MAIN
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    hl7_listener = HL7ListenerRIS()
    hl7_listener.start()
    retry_thread = RetryQueueThreadRIS()
    retry_thread.start()
    mwl_thread = threading.Thread(target=start_mwl_server, daemon=True)
    mwl_thread.start()
    root = tk.Tk()
    AuthWindowGUI(root)
    root.mainloop()
