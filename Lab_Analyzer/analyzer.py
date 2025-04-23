#!/usr/bin/env python3
import os
import socket
import threading
import sqlite3
import time
import random
import uuid
from hl7apy.core import Message
from hl7apy.parser import parse_message
from cryptography.fernet import Fernet
import getpass
import requests
import hashlib

import security

# Security CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# NETWORK CONFIG
IPS = {
    "LAB": {"ip": "172.31.9.118", "port": 5001},
    "LIS": {"ip": "172.31.17.250", "port": 5001}
}

# OTHER CONFIG
HL7_VERSION = "2.5"
QUEUE_DB = "lab_queue.db"

def init_queue_db():
    conn = sqlite3.connect(QUEUE_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_queue_lab (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            target_system TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_queue_db()

# HL7
def send_hl7_message(target_ip, target_port, message):
    """Open a TCP connection, send the encrypted HL7 message, and return the decrypted response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, target_port))
            print(f"CONNECTED TO {target_ip}:{target_port}")
            if ENCRYPTION:
                msg_to_send = security.encrypt_message(message)
            else:
                msg_to_send = message
            s.sendall(msg_to_send.encode())
            print("MESSAGE SENT")
            response = s.recv(4096).decode()
            if DECRYPTION:
                response = security.decrypt_message(response)
            print(f"RECEIVED RESPONSE: {response}")
            return response
    except Exception as e:
        print(f"Error sending HL7 message: {e}")
        return None

def create_ack(msg, code, text=""):
    """Create an HL7 ACK message."""
    ack = Message("ACK")
    ack.msh.msh_2 = "^~\\&"
    ack.msh.msh_3 = "LAB"
    if msg and hasattr(msg, 'msh'):
        ack.msh.msh_5 = msg.msh.msh_3.value
        ack.msh.msh_10 = msg.msh.msh_10.value
    else:
        ack.msh.msh_5 = "UNK"
        ack.msh.msh_10 = str(uuid.uuid4())
    ack.msh.msh_12 = HL7_VERSION
    ack.msa.msa_1 = code
    ack.msa.msa_3 = text
    return ack.to_er7().replace("\n", "\r")

# HL7 listener & connection
class HL7Listener(threading.Thread):
    def __init__(self, listen_ip="0.0.0.0", listen_port=IPS["LAB"]["port"]):
        super().__init__(daemon=True)
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.listen_ip, self.listen_port))
        self.sock.listen(5)
        print(f"LAB HL7 Listener running on {self.listen_ip}:{self.listen_port}")
    
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
            print("LAB received HL7 message:")
            print(data)
            ack = self.process_message(data)
            if ENCRYPTION:
                ack = security.encrypt_message(ack)
            conn.sendall(ack.encode())
        except Exception as e:
            print(f"Error in HL7Listener: {e}")
            try:
                if ENCRYPTION:
                    error_msg = security.encrypt_message(create_ack(None, "AR", str(e)))
                else:
                    error_msg = e
                conn.sendall(error_msg.encode())
            except:
                pass
        finally:
            conn.close()
    
    def process_message(self, data):
        print("Processing incoming lab order message...")
        try:
            msg = parse_message(data, find_groups=False)
        except Exception as e:
            return create_ack(None, "AE", "Invalid HL7 message")
        
        if not hasattr(msg, 'msh'):
            return create_ack(None, "AE", "Missing MSH segment")
        if msg.msh.msh_12.value != HL7_VERSION:
            return create_ack(msg, "AE", "Unsupported HL7 version")
        
        message_type = msg.msh.msh_9.value
        if message_type.startswith("ORM"):
            return self.handle_order(msg)
        else:
            return create_ack(msg, "AE", "Unsupported message type")
    
    def handle_order(self, msg):
        """
        Extract order details and generate test result.
        """
        try:
            orc = next(seg for seg in msg.children if seg.name == "ORC")
            order_number = orc.orc_3.value
            print(f"ORDER NUMBER : {order_number}")
            pid = next(seg for seg in msg.children if seg.name == "PID")
            patient_id = pid.pid_3.value
            name = pid.pid_5.value
            dob = pid.pid_7.value
            obr = next(seg for seg in msg.children if seg.name == "OBR")
            test_type = obr.obr_4.value
            
            print(f"Extracted order: patient_id={patient_id}, name={name}, dob={dob}, test_type={test_type}")
        except Exception as e:
            return create_ack(msg, "AE", f"Failed to extract order data: {e}")
        
        if test_type not in {
            "CBC": {"lower": 13.0, "upper": 17.0, "unit": "g/dL"},
            "CHO": {"lower": 125, "upper": 200, "unit": "mg/dL"},
            "GLU": {"lower": 70, "upper": 100, "unit": "mg/dL"},
            "LIP": {"lower": 50, "upper": 150, "unit": "mg/dL"}
        }:
            return create_ack(msg, "AE", f"Unknown test type: {test_type}")
        
        # Get range info and generate a random result
        range_info = {
            "CBC": {"lower": 13.0, "upper": 17.0, "unit": "g/dL"},
            "CHO": {"lower": 125, "upper": 200, "unit": "mg/dL"},
            "GLU": {"lower": 70, "upper": 100, "unit": "mg/dL"},
            "LIP": {"lower": 50, "upper": 150, "unit": "mg/dL"}
        }[test_type]
        lower = range_info["lower"]
        upper = range_info["upper"]
        unit = range_info["unit"]
        random_value = random.uniform(lower * 0.8, upper * 1.2)
        quantitative_result = round(random_value, 2)
        normal_range_str = f"{lower}-{upper} {unit}"
        timestamp = time.strftime("%Y%m%d%H%M%S")
        print(f"Generated test result: {quantitative_result} with reference range {normal_range_str}")
        
        # Build HL7 ORU^R01 message
        try:
            result_msg = Message("ORU_R01")
            result_msg.msh.msh_2 = "^~\\&"
            result_msg.msh.msh_3 = "LAB"    
            result_msg.msh.msh_5 = "LIS"
            result_msg.msh.msh_9 = "ORU^R01"
            result_msg.msh.msh_10 = str(uuid.uuid4())
            result_msg.msh.msh_12 = HL7_VERSION
            
            orc = result_msg.add_segment("ORC")
            orc.orc_3 = order_number
            print(f"MESSAGE TO LIS: ORDER NUMBER : {order_number}")

            pid_result = result_msg.add_segment("PID")
            pid_result.pid_3 = patient_id
            pid_result.pid_5 = name
            pid_result.pid_7 = dob
           
            obr_seg = result_msg.add_segment("OBR")
            obr_seg.obr_4 = test_type
            obr_seg.obr_7 = timestamp
            
            obx = result_msg.add_segment("OBX")
            obx.obx_1 = "1"
            obx.obx_2 = "TX"
            obx.obx_5 = str(quantitative_result)
            obx.obx_7 = normal_range_str
            obx.obx_17 = "example method"
            obx.obx_18 = "example equipment"

            hl7_text = result_msg.to_er7().replace("\n", "\r") + "\r"
            print("Constructed HL7 result message:")
            print(hl7_text)
        except Exception as e:
            return create_ack(msg, "AE", f"Error constructing result message: {e}")
        
        # Send the HL7 result message to the LIS
        response = send_hl7_message(IPS["LIS"]["ip"], IPS["LIS"]["port"], hl7_text)
        if response and "AA" in response:
            print(f"Successfully sent test result for patient {patient_id} to LIS.")
        else:
            print(f"Failed to send test result to LIS. Response: {response}")
            if ENCRYPTION:
                msg_to_send = security.encrypt_message(hl7_text)
            else:
                msg_to_send = hl7_text
            queue_message(msg_to_send, "LIS")
        return create_ack(msg, "AA")

def queue_message(message, target_system):
    """Store the unsent HL7 message in the local queue database."""
    try:
        conn = sqlite3.connect(QUEUE_DB)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO message_queue_lab (message, target_system)
            VALUES (?, ?)
        """, (message, target_system))
        conn.commit()
        conn.close()
        print("Message queued for retry.")
    except Exception as e:
        print(f"Error queueing message: {e}")

class RetryQueueThread(threading.Thread):
    def __init__(self, interval=60):
        super().__init__(daemon=True)
        self.interval = interval
    
    def run(self):
        while True:
            time.sleep(self.interval)
            self.retry_messages()
    
    def retry_messages(self):
        conn = sqlite3.connect(QUEUE_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT id, message, target_system FROM message_queue_lab")
        rows = cursor.fetchall()
        for row in rows:
            msg_id, msg, target_system = row
            if target_system == "LIS":
                target_ip = IPS["LIS"]["ip"]
                target_port = IPS["LIS"]["port"]
            else:
                continue
            if DECRYPTION:
                msg = security.decrypt_message(msg)
            response = send_hl7_message(target_ip, target_port, msg)
            if response and "AA" in response:
                cursor.execute("DELETE FROM message_queue_lab WHERE id=?", (msg_id,))
                print(f"Retried and sent queued message id {msg_id}.")
            else:
                cursor.execute("UPDATE message_queue_lab SET attempts = attempts + 1 WHERE id=?", (msg_id,))
                print(f"Retry failed for queued message id {msg_id}.")
        conn.commit()
        conn.close()


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

# Main
if __name__ == "__main__":

    if authenticate():
        listener = HL7Listener(listen_ip="0.0.0.0", listen_port=IPS["LAB"]["port"])
        listener.start()
    
        retry_thread = RetryQueueThread(interval=60)
        retry_thread.start()
    
        print("LAB Analyzer is running. Press Ctrl+C to exit.")
        while True:
            time.sleep(1)
