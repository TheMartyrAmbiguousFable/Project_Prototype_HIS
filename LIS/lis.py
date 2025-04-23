import os
import socket
import threading
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import uuid
import time
from hl7apy.core import Message, Segment
from hl7apy.parser import parse_message
from cryptography.fernet import Fernet
import hashlib

import security

# Security CONFIG
TWO_FA = True
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
ENCRYPTION = True
DECRYPTION = True

# NETWORK CONFIG
IPS = {
    'EMR': {'ip': "172.31.25.176", 'port': 2575},
    'LAB': {'ip': "172.31.9.118", 'port': 5001}
}
SELF_LISTENING_PORT = 5001


# Database Initialization
queue_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Queue")
archive_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Archive")
os.makedirs(queue_dir, exist_ok=True)
os.makedirs(archive_dir, exist_ok=True)

PATIENT_QUEUE_DB = os.path.join(queue_dir, "patient_queue.db")
TEST_RESULTS_DB = os.path.join(archive_dir, "test_results.db")

def init_patient_queue_db():
    conn = sqlite3.connect(PATIENT_QUEUE_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_queue (
            order_number INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT,
            name TEXT,
            dob TEXT,
            test_type TEXT,
            status TEXT DEFAULT 'untested'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_queue_lis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            target_system TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def init_test_results_db():
    conn = sqlite3.connect(TEST_RESULTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_results (
            test_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT,
            name TEXT,
            dob TEXT,
            test_type TEXT,
            test_result TEXT,
            method TEXT,
            equipment TEXT,
            time_of_test TEXT
        )
    """)
    conn.commit()
    conn.close()

init_patient_queue_db()
init_test_results_db()

# HL7
def build_hl7_msg(msg_type, target_system, patient_id, name=None, dob=None, test_type=None, test_result=None, order_number=None):
        msg = Message(msg_type)
        msg.msh.msh_2 = "^~\\&"
        msg.msh.msh_3 = "LIS"
        msg.msh.msh_5 = target_system
        msg.msh.msh_9 = msg_type
        msg.msh.msh_10 = str(uuid.uuid4())
        msg.msh.msh_12 = "2.5"
        
        if target_system == 'LAB':
            orc = msg.add_segment("ORC")
            orc.orc_3 = str(order_number)

        pid = msg.add_segment("PID")
        pid.pid_3 = patient_id
        pid.pid_5 = name
        pid.pid_7 = str(dob)

        
        if msg_type.upper()[:2] == 'OR':
            obr = msg.add_segment("OBR")
            obr.obr_4 = test_type
        
        hl7_text = msg.to_er7().replace("\n", "\r") + "\r"
        return hl7_text

def send_hl7_message(target_ip, target_port, message):
    """Open a TCP connection, send the encrypted HL7 message, and return the decrypted response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            print(f"CONNECTED TO {target_ip} : {target_port}")
            if ENCRYPTION:
                message = security.encrypt_message(message)
            s.sendall(message.encode())
            print("MESSAGE SENT")
            response = s.recv(4096).decode()
            if DECRYPTION:
                response = security.decrypt_message(response)
            return response
    except Exception as e:
        return None

def create_ack(msg, code, text=""):
    ack = Message("ACK")
    ack.msh.msh_2 = "^~\\&"
    ack.msh.msh_3 = "LIS"
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

# HL7 Listener 
class HL7Listener(threading.Thread):
    """
    This thread listens for incoming HL7 messages from the EMR and Lab Analyzer.
    """
    def __init__(self, listen_ip="0.0.0.0", listen_port=SELF_LISTENING_PORT):
        super().__init__(daemon=True)
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.listen_ip, self.listen_port))
        self.sock.listen(5)
        print(f"LIS HL7 Listener running on {self.listen_ip}:{self.listen_port}")
    
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
            print("Received HL7 message:")
            print(data)
            ack = self.process_message(data)
            if ENCRYPTION:
                ack = security.encrypt_message(ack)
            conn.sendall(ack.encode())
        except Exception as e:
            print(f"Error in HL7Listener: {e}")
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
        print("PROCESSING INCOMING MESSAGE")
        try:
            msg = parse_message(data)
            print("MESSAGE PARSED")
        except Exception as e:
            print("CAN'T PARSE INCOMING MESSAGE")
            return create_ack(None, "AE", "Invalid HL7 message")
        
        if not hasattr(msg, 'msh'):
            print("INVALID MESSAGE: NO MSH SEGMENT")
            return create_ack(None, "AE", "Missing MSH segment")
        if msg.msh.msh_12.value != "2.5":
            print("INVALID HL7 VERSION")
            return create_ack(msg, "AE", "Unsupported HL7 version")
        
        message_type = msg.msh.msh_9.value
        if message_type.startswith("ORM"):
            return self.handle_order(parse_message(data, find_groups=False))
        elif message_type.startswith("ORU"):
            return self.handle_result(parse_message(data, find_groups=False))
        elif message_type.startswith("QRY"):
            return self.handle_query(msg)
        else:
            return create_ack(msg, "AE", "Unsupported message type")
    
    def handle_order(self, msg):
        try:
            print(f"HANDLING ORDER MESSAGE: \n{msg}")
            pid = next((seg for seg in msg.children if seg.name == "PID"), None)
            patient_id = pid.pid_3.value
            name = pid.pid_5.value
            dob = pid.pid_7.value
            obr = next((seg for seg in msg.children if seg.name == "OBR"), None)
            if not obr:
                return create_ack(msg, "AE", "Missing OBR segment")
            obr_field = obr.obr_4.value
            test_type = obr_field[4:7]
            print(f"Extracted test type: {test_type}")
        except Exception as e:
            return create_ack(msg, "AE", f"Failed to extract order data: {e}")
        
        try:
            conn = sqlite3.connect(PATIENT_QUEUE_DB)
            cursor = conn.cursor()
            if ENCRYPTION:
                name = security.encrypt_message(name)
                dob = security.encrypt_message(dob)
                test_type = security.encrypt_message(test_type)
            cursor.execute("""
                INSERT OR REPLACE INTO patient_queue (patient_id, name, dob, test_type, status)
                VALUES (?, ?, ?, ?, 'untested')
            """, (patient_id, name, dob, test_type))
            conn.commit()
            conn.close()
            print(f"Stored order for patient {patient_id} in patient_queue.")
        except Exception as e:
            return create_ack(msg, "AE", f"Database error: {e}")
        
        return create_ack(msg, "AA")
    
    def handle_result(self, msg):
        try:
            print("START PROCESSING TEST RESULT")

            orc = next((seg for seg in msg.children if seg.name == "ORC"), None)
            order_number = orc.orc_3.value

            pid = next((seg for seg in msg.children if seg.name == "PID"), None)
            patient_id = pid.pid_3.value
            name = pid.pid_5.value
            dob = pid.pid_7.value

            obr = next((seg for seg in msg.children if seg.name == "OBR"), None)
            test_type = obr.obr_4.value
            time_of_test = obr.obr_7.value

            obx = next((seg for seg in msg.children if seg.name == "OBX"), None)
            result_value = obx.obx_5.value
            reference_range = obx.obx_7.value
            test_method = obx.obx_17.value
            test_equipment = obx.obx_18.value

            test_result = result_value + "/" + reference_range

            timestamp = msg.msh.msh_7.value if hasattr(msg.msh, 'msh_7') else time.strftime("%Y%m%d%H%M%S")
        except Exception as e:
            return create_ack(msg, "AE", f"Failed to extract result data: {e}")
        
        # Update patient_queue status
        try:
            conn = sqlite3.connect(PATIENT_QUEUE_DB)
            cursor = conn.cursor()
            cursor.execute("UPDATE patient_queue SET status = 'tested' WHERE order_number=?", (order_number, ))
            conn.commit()
            conn.close()
            print(f"Updated patient {patient_id} status to 'tested'.")
        except Exception as e:
            return create_ack(msg, "AE", f"Database error updating status: {e}")
        
        # Store result in test_results archive
        try:
            conn = sqlite3.connect(TEST_RESULTS_DB)
            cursor = conn.cursor()
            if ENCRYPTION:
                name = security.encrypt_message(name)
                dob = security.encrypt_message(dob)
                test_type = security.encrypt_message(test_type)
                test_result = security.encrypt_message(test_result)
                test_method = security.encrypt_message(test_method)
                test_equipment = security.encrypt_message(test_equipment)
                timestamp = security.encrypt_message(timestamp)
            cursor.execute("""
                INSERT INTO test_results (patient_id, name, dob, test_type, test_result, method, equipment, time_of_test)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (patient_id, name, dob, test_type, test_result, test_method, test_equipment, timestamp))
            conn.commit()
            conn.close()
            print(f"Stored test result for patient {patient_id} in test_results.")
        except Exception as e:
            return create_ack(msg, "AE", f"Database error storing test result: {e}")
        
        # Build result summary
        result_summary = f"TST{test_type}: {result_value}/{reference_range}; time:{timestamp}"
        try:
            msg_to_emr = self.build_msg_to_emr(patient_id, test_type, time_of_test, result_summary)
            response = send_hl7_message(IPS["EMR"]["ip"], IPS["EMR"]["port"], msg_to_emr)
            if response and "AA" in response:
                print(f"Forwarded test result for {patient_id} to EMR.")
                return create_ack(msg, "AA")
            else:
                print(f"Failed to forward result to EMR, response: {response}")
                conn = sqlite3.connect(PATIENT_QUEUE_DB)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO message_queue_lis (message, target_system)
                    VALUES (?, ?)
                """, (msg_to_emr, "EMR"))
                conn.commit()
                conn.close()
        except:
            messagebox.showerror("Error", "Something went wrong when sending msg to EMR.")
        return create_ack(msg, "AA")
        
    def build_msg_to_emr(self, patient_id, test_type, time, result):    
        try:
            result_msg = Message("ORU_R01")
            result_msg.msh.msh_2 = "^~\\&"
            result_msg.msh.msh_3 = "LIS"
            result_msg.msh.msh_5 = "EMR"
            result_msg.msh.msh_9 = "ORU^R01"
            result_msg.msh.msh_10 = str(uuid.uuid4())
            result_msg.msh.msh_12 = "2.5"

            pid = result_msg.add_segment("PID")
            pid.pid_3 = patient_id

            obr = result_msg.add_segment("OBR")
            obr.obr_4 = test_type
            obr.obr_7 = time

            obx = result_msg.add_segment("OBX")
            obx.obx_1 = "1"
            obx.obx_2 = "TX"
            obx.obx_5 = result
            hl7_text = result_msg.to_er7().replace("\n", "\r") + "\r"
            return hl7_text
        except:
            print("FAILED TO CONSTRUCT MESSAGE FOR EMR")
            return 
            
    def handle_query(self, msg):
        print("Received HL7 query message. Functionality not implemented yet.")
        return create_ack(msg, "AA", "Query functionality not implemented")

# Retry queue
class RetryQueueThread(threading.Thread):
    def __init__(self, interval=60):
        super().__init__(daemon=True)
        self.interval = interval
    
    def run(self):
        while True:
            time.sleep(self.interval)
            self.retry_messages()
    
    def retry_messages(self):
        conn = sqlite3.connect(PATIENT_QUEUE_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT id, message, target_system FROM message_queue_lis")
        rows = cursor.fetchall()
        for row in rows:
            try:
                msg_id, msg_text, target_system = row
                target_ip = IPS[target_system]['ip']
                target_port = IPS[target_system]['port']
                response = send_hl7_message(target_ip, target_port, msg_text)
            except:
                response = None
                print("TARGET SYSTEM NOT FOUND")
            if response and "AA" in response:
                cursor.execute("DELETE FROM message_queue_lis WHERE id=?", (msg_id,))
                print(f"Successfully retried queued message id {msg_id}.")
            else:
                cursor.execute("UPDATE message_queue_lis SET attempts = attempts + 1 WHERE id=?", (msg_id,))
                print(f"Retry failed for message id {msg_id}.")
            conn.commit()
        conn.close()

# GUI
class AuthWindowGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LIS Workstation - Authentication")
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
                MainApp(self.token)
            else:
                messagebox.showerror("Error", response.json().get("error", "Authentication failed"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

class MainApp:
    def __init__(self, token):
        self.token = token
        self.root = tk.Tk()
        self.root.title("LIS Workstation")
        self.root.geometry("800x600")
        self.setup_ui()
        self.root.mainloop()
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="View Patients", command=self.view_patients).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="View Test Results", command=self.view_test_results).pack(side=tk.LEFT, padx=10)
    
    def view_patients(self):
        window = tk.Toplevel(self.root)
        window.title("Patient Queue")
        window.geometry("700x400")
        
        filter_frame = ttk.Frame(window)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(filter_frame, text="Filter by Patient ID:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(filter_frame)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        tree = ttk.Treeview(window, columns=("Order#", "Patient ID", "Name", "DOB", "Test Type", "Status"), show="headings")
        tree.heading("Order#", text="Order #")
        tree.heading("Patient ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="DOB")
        tree.heading("Test Type", text="Test Type")
        tree.heading("Status", text="Status")
        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        def load_data(filter_text=""):
            for i in tree.get_children():
                tree.delete(i)
            conn = sqlite3.connect(PATIENT_QUEUE_DB)
            cursor = conn.cursor()
            if filter_text:
                cursor.execute("SELECT order_number, patient_id, name, dob, test_type, status FROM patient_queue WHERE patient_id LIKE ?", ('%' + filter_text + '%',))
            else:
                cursor.execute("SELECT order_number, patient_id, name, dob, test_type, status FROM patient_queue")
            rows = cursor.fetchall()
            conn.close()
            for row in rows:
                name = security.decrypt_message(row[2]) if DECRYPTION else row[2]
                dob = security.decrypt_message(row[3]) if DECRYPTION else row[3]
                test_type = security.decrypt_message(row[4]) if DECRYPTION else row[4]
                tree.insert("", "end", values=(row[0], row[1], name, dob, test_type, row[5]))
        
        load_data()
        filter_entry.bind("<KeyRelease>", lambda e: load_data(filter_entry.get().strip()))
        
        menu = tk.Menu(window, tearoff=0)
        menu.add_command(label="Remove Patient", command=lambda: remove_selected())
        menu.add_command(label="Send Order to Test", command=lambda: send_order())
        
        def on_right_click(event):
            iid = tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid)
                menu.post(event.x_root, event.y_root)
        tree.bind("<Button-3>", on_right_click)
        
        def remove_selected():
            selected = tree.selection()
            if not selected:
                return
            order_number = tree.item(selected[0])["values"][0]
            if messagebox.askyesno("Confirm", f"Remove patient order #{order_number}?"):
                conn = sqlite3.connect(PATIENT_QUEUE_DB)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM patient_queue WHERE order_number=?", (order_number,))
                conn.commit()
                conn.close()
                tree.delete(selected[0])
        
        def send_order():
            selected = tree.selection()
            if not selected:
                return
            order_number = tree.item(selected[0])["values"][0]
            patient_id = tree.item(selected[0])["values"][1]
            name = tree.item(selected[0])["values"][2]
            dob = tree.item(selected[0])["values"][3]
            test_type = tree.item(selected[0])["values"][4]
            if tree.item(selected[0])["values"][5] != "untested":
                messagebox.showinfo("Info", "Order already sent or processed.")
                return
            hl7_text = build_hl7_msg("ORM_O01", "LAB", patient_id, name, dob, test_type, order_number=order_number)
            response = send_hl7_message(IPS["LAB"]['ip'], IPS["LAB"]['port'], hl7_text)

            if response and "AA" in response:
                conn = sqlite3.connect(PATIENT_QUEUE_DB)
                cursor = conn.cursor()
                cursor.execute("UPDATE patient_queue SET status = 'pending' WHERE order_number=?", (order_number,))
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", f"Order for patient {patient_id} sent to Lab Analyzer.")
            else:
            # Queue the message for retry if sending fails
                conn = sqlite3.connect(PATIENT_QUEUE_DB)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO message_queue_lis (message, target_system)
                    VALUES (?, ?)
                """, (hl7_text, "LAB"))
                conn.commit()
                conn.close()
                messagebox.showerror("Error", "Failed to send order to Lab Analyzer. Message queued for retry.")


            load_data(filter_entry.get().strip())
    
    def view_test_results(self):
        window = tk.Toplevel(self.root)
        window.title("Test Results Archive")
        window.geometry("700x400")
        
        filter_frame = ttk.Frame(window)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(filter_frame, text="Filter by Patient ID:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(filter_frame)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        # Updated columns: include Test ID as left-most column.
        tree = ttk.Treeview(window, columns=("Test ID", "Patient ID", "Name", "DOB", "Test Type", "Test Result", "Method", "Equipment", "Timestamp"), show="headings")
        tree.heading("Test ID", text="Test ID")
        tree.heading("Patient ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="DOB")
        tree.heading("Test Type", text="Test Type")
        tree.heading("Test Result", text="Test Result")
        tree.heading("Method", text="Test Method")
        tree.heading("Equipment", text="Test Equipment")
        tree.heading("Timestamp", text="Time of Test")

        tree.column("Test ID", width=80, anchor="center")
        tree.column("Patient ID", width=100, anchor="center")
        tree.column("Name", width=80)
        tree.column("DOB", width=100)
        tree.column("Test Type", width=120)
        tree.column("Test Result", width=200)
        tree.column("Method", width=120)
        tree.column("Equipment", width=120)
        tree.column("Timestamp", width=150)

        tree.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        def load_data(filter_text=""):
            for i in tree.get_children():
                tree.delete(i)
            conn = sqlite3.connect(TEST_RESULTS_DB)
            cursor = conn.cursor()
            if filter_text:
                cursor.execute('''SELECT test_id, patient_id, name, dob, test_type, test_result, method, equipment, time_of_test 
                FROM test_results WHERE patient_id LIKE ?''', ('%' + filter_text + '%',))
            else:
                cursor.execute('''SELECT test_id, patient_id, name, dob, test_type, test_result, method, equipment, time_of_test 
                FROM test_results''')
            rows = cursor.fetchall()
            conn.close()
            for row in rows:
                name = security.decrypt_message(row[2]) if DECRYPTION else row[2]
                dob = security.decrypt_message(row[3]) if DECRYPTION else row[3]
                test_type = security.decrypt_message(row[4]) if DECRYPTION else row[4]
                test_result = security.decrypt_message(row[5]) if DECRYPTION else row[5]
                method = security.decrypt_message(row[6]) if DECRYPTION else row[6]
                equipment = security.decrypt_message(row[7]) if DECRYPTION else row[7]
                timestamp = security.decrypt_message(row[8]) if DECRYPTION else row[8]
                tree.insert("", "end", values=(row[0], row[1], name, dob, test_type, test_result, method, equipment, timestamp))
        
        load_data()
        filter_entry.bind("<KeyRelease>", lambda e: load_data(filter_entry.get().strip()))
        
        menu = tk.Menu(window, tearoff=0)
        menu.add_command(label="Remove Test Result", command=lambda: remove_selected())
        
        def on_right_click(event):
            iid = tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid)
                menu.post(event.x_root, event.y_root)
        tree.bind("<Button-3>", on_right_click)
        
        def remove_selected():
            selected = tree.selection()
            if not selected:
                return
            test_id = tree.item(selected[0])["values"][0]
            if messagebox.askyesno("Confirm", f"Remove test result with Test ID {test_id}?"):
                conn = sqlite3.connect(TEST_RESULTS_DB)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM test_results WHERE test_id=?", (test_id,))
                conn.commit()
                conn.close()
                tree.delete(selected[0])


hl7_listener = HL7Listener(listen_port=SELF_LISTENING_PORT)
hl7_listener.start()

retry_thread = RetryQueueThread(interval=60)
retry_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    AuthWindowGUI(root)
    root.mainloop()
