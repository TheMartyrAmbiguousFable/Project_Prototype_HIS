import socket
import threading
import logging
import sqlite3
import time
from hl7apy.parser import parse_message
from hl7apy.core import Message
from cryptography.fernet import Fernet
import requests
import getpass
import hashlib

import security

# Security CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# NETWORK & DATABASE CONFIG
IPS = {
    "EMR": {"ip": "172.31.25.176", "port": 2575},
    "LIS": {"ip": "172.31.17.250", "port": 5001},
    "RIS": {"ip": "172.31.45.74", "port": 5001}
}
DB_PATH = "/var/emr/data/patients.db"
HL7_PORT = IPS["EMR"]["port"]

logging.basicConfig(level=logging.INFO)

class HL7MessageBroker:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((IPS["EMR"]["ip"], HL7_PORT))
        self.socket.listen(5)
        logging.info(f"HL7 broker listening on {IPS['EMR']['ip']}:{HL7_PORT}")
        self.retry_thread = threading.Thread(target=self.retry_queue, daemon=True)
        self.retry_thread.start()

    def start(self):
        while True:
            conn, addr = self.socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn,))
            client_thread.start()

    def handle_client(self, conn):
        try:
            data = conn.recv(4096).decode()
            if DECRYPTION:
                data = security.decrypt_message(data)
            logging.info(f"Received:\n{data}")
            ack = self.process_message(data)
            if ENCRYPTION:
                ack = security.encrypt_message(ack)
            conn.send(ack.encode())
        except Exception as e:
            logging.error(f"Error: {str(e)}")
            if ENCRYPTION:
                error_msg = security.encrypt_message(self.create_ack(None, "AR", str(e)))
            else:
                error_msg = self.create_ack(None, "AR", str(e))
            conn.send(error_msg.encode())
        finally:
            conn.close()

    def process_message(self, data):
        
        msg = parse_message(data)        

        if not hasattr(msg, 'msh'):
            return self.create_ack(None, "AE", "Missing MSH segment")
        if msg.msh.msh_12.value != "2.5":
            return self.create_ack(msg, "AE", "Unsupported HL7 version")
        print("MSH FOUND")

        handlers = {
            'ADT^A01': self.handle_adt,
            'ADT^A03': self.handle_discharge,
            'ORM^O01': self.route_order,
            'ORU^R01': self.route_result,
            'QRY^A19': self.handle_query,
            }
        
        message_type = msg.msh.msh_9.value
        print(message_type)

        handler = handlers.get(message_type)
        print("handler selected")

        if handler:
            if message_type[:2] == 'OR':
                msg = parse_message(data, find_groups=False)
            return handler(msg)
        else:
            return self.create_ack(msg, "AE", "Unsupported message type")

    def handle_adt(self, msg):
        print("IN FUNCTION: HANDLE_ADT")
        if not msg.pid.pid_3.value.startswith('P'):
            return self.create_ack(msg, "AE", "Invalid patient ID format")
        self.store_patient_data(msg)
        return self.create_ack(msg, "AA")

    def handle_discharge(self, msg):
        print("IN FUNCTION: HANDLE_DISCHARGE")
        if not msg.pid.pid_3.value.startswith('P'):
            return self.create_ack(msg, "AE", "Invalid patient ID format")
        self.remove_patient(msg)
        return self.create_ack(msg, "AA")

    def route_order(self, msg):
        print("IN FUNCTION: ROUTE_ORDER")
        order_type = None
        obr_segment = next((seg for seg in msg.children if seg.name == "OBR"), None)
        if obr_segment:
            order_type = obr_segment.obr_4.value[:3]
        print(f"order_type: {order_type}")
        if order_type == "DOC":
            self.handle_doc_cons(msg)
            return self.create_ack(msg, "AA")
        target_system = {"LAB": "LIS", "RAD": "RIS"}.get(order_type)
        if not target_system:
            return self.create_ack(msg, "AE", "Invalid order type")

        self.forward_to_system(msg, target_system)
        return self.create_ack(msg, "AA")

    def route_result(self, msg):
        print("IN FUNCTION: ROUTE_RESULT")
        try:
            pid = next(seg for seg in msg.children if seg.name == "PID")
            patient_id = pid.pid_3.value
            obx = next(seg for seg in msg.children if seg.name == "OBX")
            result_type = obx.obx_5.value[:3]
            result = obx.obx_5.value[3:]
            if result_type == "TST":
                obr = next(seg for seg in msg.children if seg.name == "OBR")
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE patients 
                    SET test_result = 
                        CASE 
                            WHEN test_result IS NULL OR test_result = '' THEN ?
                            ELSE test_result || '##' || ?
                        END
                    WHERE patient_id = ?
                """, (result, result, patient_id))
                conn.commit()
                conn.close()
                logging.info(f"Updated test result for {patient_id}")
            elif result_type == "CMT":
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE patients 
                    SET comment = 
                        CASE 
                            WHEN comment IS NULL OR comment = '' THEN ?
                            ELSE comment || '##' || ?
                        END
                    WHERE patient_id = ?
                """, (result, result, patient_id))
                conn.commit()
                conn.close()
                logging.info(f"Updated test comment for {patient_id}")
        except Exception as e:
            logging.error(f"Failed to process comment: {str(e)}")
        return self.create_ack(msg, "AA")

    def handle_query(self, msg):
        print("IN FUNCTION: HANDLE_QUERY")
        try:
            if not hasattr(msg, 'qrd'):
                return self.create_ack(msg, "AE", "Missing QRD segment")
            INFO_DICT = {'DEM': 'ssn, phone', 'CLN': 'test_result, comment'}
            PAT = 'patient_id, name, dob, '
            query_subject = msg.qrd.qrd_9.value if msg.qrd.qrd_9.value else ''
            query_fields = PAT + INFO_DICT[query_subject] if query_subject else PAT
            
            TABLE_MAP = {'DOC_SCH': 'doctor_cons'}
            if hasattr(msg, 'qrf'):
                print("Found qrf segment")
                table = TABLE_MAP[msg.qrf.qrf_1.value] if msg.qrf.qrf_1.value else 'patients'
            else:
                table = 'patients'
                
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            print(f"Searching from table: {table}")
            if msg.qrd.qrd_7.value == '1':
                print("Retrieve 1 patient")
                patient_id = msg.qrd.qrd_8.value
                if not patient_id:
                    return self.create_ack(msg, "AE", "Missing patient ID in QRD.8")
                cursor.execute(f"SELECT {query_fields} FROM {table} WHERE patient_id=?", (patient_id,))
                patients = [cursor.fetchone()]
            elif msg.qrd.qrd_7.value == '-1':
                print("Retrieve all patients")
                if table == 'doctor_cons':
                    query_fields = "order_id, patient_id, name, dob, consultation, booked_at"
                    cursor.execute(f"SELECT {query_fields} FROM {table} WHERE status='pending'")
                else:
                    cursor.execute(f"SELECT {query_fields} FROM {table}")
                patients = cursor.fetchall()
            else:
                print("Retrieve multiple patients")
                rows_num = int(msg.qrd.qrd_7.value)
                cursor.execute(f"SELECT {query_fields} FROM {table}")
                if table == 'doctor_cons':
                    query_fields = "order_id, patient_id, name, dob, consultation, booked_at"
                    cursor.execute(f"SELECT {query_fields} FROM {table} WHERE status='pending'")
                else:
                    cursor.execute(f"SELECT {query_fields} FROM {table}")
                patients = cursor.fetchmany(rows_num)
            conn.close()
            if not patients:
                return self.create_ack(msg, "AE", f"Patient {patient_id} not found")
            # Build response message
            rsp = Message("RSP_K11")
            rsp.msh.msh_3 = "EMR"
            rsp.msh.msh_5 = msg.msh.msh_3.value
            rsp.msh.msh_9 = "RSP^K11"
            rsp.msh.msh_10 = msg.msh.msh_10.value
            rsp.msh.msh_12 = "2.5"
            msa = rsp.add_segment("MSA")
            msa.msa_1 = "AA"
            msa.msa_2 = msg.msh.msh_10.value
            qak = rsp.add_segment("QAK")
            qak.qak_1 = msg.qrd.qrd_2.value
            qak.qak_2 = "OK"
            for patient in patients:
                pid_seg = rsp.add_segment("PID")
                if table == 'doctor_cons':
                    pid_seg.pid_3 = patient[1] 
                    pid_seg.pid_5 = patient[2]  
                    pid_seg.pid_7 = patient[3]  
                elif table == 'patients' and query_subject == "DEM":
                    pid_seg.pid_3 = patient[0] 
                    pid_seg.pid_5 = patient[1] if patient[1] else ""
                    pid_seg.pid_7 = patient[2] if patient[2] else ""
                    pid_seg.pid_19 = patient[3] if patient[3] else ""
                    pid_seg.pid_13 = patient[4] if patient[4] else ""
                elif table == 'patients' and query_subject == "CLN":
                    pid_seg.pid_3 = patient[0]
                    pid_seg.pid_5 = patient[1] if patient[1] else ""
                    pid_seg.pid_7 = patient[2] if patient[2] else ""
                    obx_seg = rsp.add_segment("OBX")
                    obx_seg.obx_5 = patient[3] if patient[3] else ""
                    nte_seg = rsp.add_segment("NTE")
                    nte_seg.nte_3 = patient[4] if patient[4] else ""
            return rsp.to_er7().replace('\n', '\r')
        except Exception as e:
            logging.error(f"Query error: {str(e)}")
            return self.create_ack(msg, "AE", f"Query failed: {str(e)}")
    
    def handle_doc_cons(self, msg):
        print("IN FUNCTION: HANDLE_DOC_CONS")
        try:
            # Extract information from the message
            patient_id = msg.pid.pid_3.value if hasattr(msg, 'pid') else "Unknown"
            name = msg.pid.pid_5.value if hasattr(msg, 'pid') else ""
            dob = msg.pid.pid_7.value if hasattr(msg, 'pid') else ""
            order_id = msg.msh.msh_10.value if hasattr(msg, 'msh') else ""

            obr = next((seg for seg in msg.children if seg.name == "OBR"), None)
            consultation = obr.obr_4.value[4:7]
            print(f"Consultation: {consultation}")
            print(f"Order_id: {order_id}")
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            # Create the doctor_cons table if it does not exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS doctor_cons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_id TEXT,
                    patient_id TEXT,
                    name TEXT,
                    dob TEXT,
                    consultation TEXT,
                    status TEXT DEFAULT 'pending',
                    booked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Insert the consultation record
            cursor.execute("""
                INSERT INTO doctor_cons (order_id, patient_id, name, dob, consultation)
                VALUES (?, ?, ?, ?, ?)
            """, (order_id, patient_id, name, dob, consultation))
            conn.commit()
            conn.close()
            logging.info(f"Inserted doctor consultation for patient_id: {patient_id}")
        except Exception as e:
            logging.error(f"Error in handle_doc_cons: {str(e)}")

    def create_ack(self, msg, code, text=""):
        print("IN FUNCTION: CREATE_ACK")
        ack = Message("ACK")
        ack.msh.msh_3 = "EMR"
        if msg:
            ack.msh.msh_5 = msg.msh.msh_3.value
            ack.msh.msh_10 = msg.msh.msh_10.value
        ack.msa.msa_1 = code
        ack.msa.msa_3 = text
        return ack.to_er7().replace('\n', '\r')

    def forward_to_system(self, msg, system):
        print("IN FUNCTION: FORWARD_TO_SYSTEM")
        try:
            target_ip = IPS[system]["ip"]
            target_port = IPS[system]["port"]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((target_ip, target_port))
                print(f"CONNECTED TO {system}")
                if ENCRYPTION:
                    s.sendall(security.encrypt_message(msg.to_er7().replace('\n', '\r')).encode())
                else:
                    s.sendall(msg.to_er7().replace('\n', '\r').encode())
                print(f"MESSAGE SENT TO {system}")
                s.recv(1024)
        except Exception as e:
            logging.error(f"Failed to forward to {system}. Queuing message.")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            if ENCRYPTION:
                msg_to_insert = security.encrypt_message(msg.to_er7().replace('\n', '\r'))
            else:
                msg_to_insert = msg.to_er7().replace('\n', '\r')
            cursor.execute("""
                INSERT INTO message_queue (message, target_system)
                VALUES (?, ?)
            """, (msg_to_insert, system))
            conn.commit()
            conn.close()

    def retry_queue(self):
        print("IN FUNCTION: RETRY_QUEUE")
        import time
        while True:
            time.sleep(60)
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                    CREATE TABLE IF NOT EXISTS message_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT NOT NULL,
                    target_system TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("SELECT id, message, target_system FROM message_queue")
            queue = cursor.fetchall()
            for msg_id, msg_data, target in queue:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(5)
                        s.connect((IPS[target]["ip"], IPS[target]["port"]))
                        s.sendall(msg_data.encode())
                        s.recv(1024)
                    cursor.execute("DELETE FROM message_queue WHERE id=?", (msg_id,))
                except Exception as e:
                    cursor.execute("UPDATE message_queue SET attempts = attempts + 1 WHERE id=?", (msg_id,))
            conn.commit()
            conn.close()

    def store_patient_data(self, msg):
        print("IN FUNCTION: STORE_PATIENT_DATA")
        try:
            patient_id = msg.pid.pid_3.value
            name = msg.pid.pid_5.value
            dob = msg.pid.pid_7.value
            ssn = msg.pid.pid_19.value if hasattr(msg.pid, 'pid_19') else ""
            phone = msg.pid.pid_13.value if hasattr(msg.pid, 'pid_13') else ""
        except Exception as e:
            logging.error(f"Failed to extract patient data: {str(e)}")
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS patients (
                    patient_id TEXT PRIMARY KEY,
                    name TEXT,
                    dob TEXT,
                    ssn TEXT,
                    phone TEXT,
                    test_result TEXT DEFAULT '',
                    comment TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                INSERT OR REPLACE INTO patients 
                (patient_id, name, dob, ssn, phone, test_result, comment)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (patient_id, name, dob, ssn, (phone), '', ''))
            conn.commit()
            conn.close()
            logging.info(f"Stored patient data for patient_id: {patient_id}")
        except Exception as e:
            logging.error(f"Database error: {str(e)}")

    def remove_patient(self, msg):
         print("IN FUNCTION: REMOVE_PATIENT")
         patient_id = msg.pid.pid_3.value
         conn = sqlite3.connect(DB_PATH)
         cursor = conn.cursor()
         cursor.execute("DELETE FROM patients WHERE patient_id = ?", (patient_id,))
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

if __name__ == "__main__":
    if authenticate():
        broker = HL7MessageBroker()
        broker.start()
