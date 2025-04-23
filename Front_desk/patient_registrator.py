import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import requests
import uuid
from hl7apy.core import Message, Segment
from hl7apy.parser import parse_message
from cryptography.fernet import Fernet
import hashlib
import datetime

import security

# SECURITY CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth" 
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# NETWORK CONFIG
IPS = {
    "EMR": {"ip": "172.31.25.176", "port": 2575}
}

# Authentication
class AuthWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Hospital Front Desk - Authentication")
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

# Main
class MainApp:
    def __init__(self, token):
        self.token = token
        self.root = tk.Tk()
        self.root.title("Hospital Front Desk")
        self.root.geometry("800x600")
        self.setup_ui()
        self.root.mainloop()
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="View Patients", command=self.view_patients).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Add Patient", command=self.add_patient).pack(side=tk.LEFT, padx=10)
    
    def add_patient(self):
        reg_window = tk.Toplevel(self.root)
        reg_window.title("Patient Registration")
        reg_window.geometry("400x300")

        ttk.Label(reg_window, text="Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        name_entry = ttk.Entry(reg_window)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(reg_window, text="Date of Birth:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        dob_frame = ttk.Frame(reg_window)
        dob_frame.grid(row=1, column=1, padx=5, pady=5)
        dob_year_entry = ttk.Entry(dob_frame, width=6)
        dob_year_entry.grid(row=0, column=0)
        ttk.Label(dob_frame, text="-").grid(row=0, column=1)
        dob_month_entry = ttk.Entry(dob_frame, width=4)
        dob_month_entry.grid(row=0, column=2)
        ttk.Label(dob_frame, text="-").grid(row=0, column=3)
        dob_day_entry = ttk.Entry(dob_frame, width=4)
        dob_day_entry.grid(row=0, column=4)

        ttk.Label(reg_window, text="SSN:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ssn_entry = ttk.Entry(reg_window)
        ssn_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(reg_window, text="Phone:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        phone_entry = ttk.Entry(reg_window)
        phone_entry.grid(row=3, column=1, padx=5, pady=5)

        
        def register():
            try: 
                year, month, day = int(dob_year_entry.get().strip()), int(dob_month_entry.get().strip()), int(dob_day_entry.get().strip())
                assert 1900 <= year <= 2025 and month in range(1, 13)
                if month in (1, 3, 5, 7, 8, 10, 12):
                    assert day in range(1, 32)
                elif month != 2:
                    assert day in range(1, 31)
                elif year % 4 != 0:
                    assert day in range(1, 29)
                else:
                    assert day in range(1, 30)
                
                month_str = '0'+str(month) if month < 10 else str(month)
                day_str = '0'+str(day) if day < 10 else str(day)
                dob = str(year) + month_str + day_str
            except:
                print("Invalid Date of Birth")

            try:
                patient_data = {
                    "name": name_entry.get().strip(),
                    "dob": dob,
                    "ssn": ssn_entry.get().strip(),
                    "phone": phone_entry.get().strip()
                }
                if not all(patient_data.values()):
                    raise ValueError("All fields are required")
                
                # Build HL7 ADT^A01 message for patient registration.
                msg = Message("ADT_A01")
                msg.msh.msh_2 = "^~\\&"
                msg.msh.msh_3 = "FRD"
                msg.msh.msh_5 = "EMR"        
                msg.msh.msh_9 = "ADT^A01"
                msg.msh.msh_10 = str(uuid.uuid4())
                msg.msh.msh_11 = "P"
                msg.msh.msh_12 = "2.5"
                
                pid = msg.add_segment("PID")
                # Generate patient ID
                patient_id = f"P{uuid.uuid4().int % 10**8:08d}"
                pid.pid_3 = patient_id
                pid.pid_5 = patient_data["name"]
                pid.pid_7 = patient_data["dob"]
                pid.pid_19 = patient_data["ssn"]
                pid.pid_13 = patient_data["phone"]
                
                hl7_message = msg.to_er7().replace("\n", "\r") + "\r"
                ack = self.send_hl7(hl7_message)
                if "AA" in ack:
                    messagebox.showinfo("Success", f"Patient {patient_id} registered")
                    reg_window.destroy()
                else:
                    messagebox.showerror("Error", f"Registration failed:\n{ack}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(reg_window, text="Register", command=register).grid(row=4, column=0, columnspan=2, pady=10)
    
    def view_patients(self):
        window = tk.Toplevel(self.root)
        window.title("Registered Patients")
        window.geometry("700x400")
        
        filter_frame = ttk.Frame(window)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(filter_frame, text="Filter by Patient ID:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(filter_frame)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        tree = ttk.Treeview(window, columns=("ID", "Name", "DOB", "Phone"), show="headings")
        tree.heading("ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="Date of Birth")
        tree.heading("Phone", text="Phone")
        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        def load_data(filter_text=""):
            # Send HL7 QRY message to EMR to get patients.
            try:
                msg = Message("QRY_A19")
                msg.msh.msh_2 = "^~\\&"
                msg.msh.msh_3 = "FRD"
                msg.msh.msh_5 = "EMR"
                msg.msh.msh_9 = "QRY^A19"
                msg.msh.msh_10 = str(uuid.uuid4())
                msg.msh.msh_12 = "2.5"
                qrd = msg.add_segment("QRD")
                qrd.qrd_1 = datetime.now().strftime("%Y%m%d%H%M")
                qrd.qrd_2 = "R"
                qrd.qrd_3 = "I"
                qrd.qrd_7 = "-1"  # Request all patients
                qrd.qrd_9 = "DEM"
                
                hl7_query = msg.to_er7().replace("\n", "\r")
                response = self.send_hl7(hl7_query)
                patients = self.parse_query_response(response)
            except Exception as e:
                messagebox.showerror("Error", f"Query failed: {e}")
                return
            
            # Clear current entries and load filtered results
            for i in tree.get_children():
                tree.delete(i)
            for patient in patients:
                if filter_text and filter_text not in patient["id"]:
                    continue
                dob_str = patient["dob"]
                dob_display = dob_str[:4] + '-' + dob_str[4:6] + dob_str[6:]
                tree.insert("", "end", values=(patient["id"], patient["name"], dob_display, patient["phone"]))
        
        load_data()
        filter_entry.bind("<KeyRelease>", lambda e: load_data(filter_entry.get().strip()))
        
        # Right-click context menu for each patient row.
        menu = tk.Menu(window, tearoff=0)
        menu.add_command(label="Remove Patient", command=lambda: remove_selected())
        menu.add_command(label="Book Lab Test", command=lambda: book_order("LAB"))
        menu.add_command(label="Book Radiology", command=lambda: book_order("RAD"))
        menu.add_command(label="Doctor Consultation", command=lambda: book_order("DOC"))
        
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
            patient_id = tree.item(selected[0])["values"][0]
            if messagebox.askyesno("Confirm", f"Remove patient {patient_id}?"):
                self.send_removal(patient_id)
                tree.delete(selected[0])
        
        def book_order(order_type):
            selected = tree.selection()
            if not selected:
                return
            patient_id = tree.item(selected[0])["values"][0]
            name = tree.item(selected[0])["values"][1]
            dob = tree.item(selected[0])["values"][2].replace('-', '')
            if order_type == "LAB":
                # Prompt for test type choice
                test = self.get_test_type()
                if not test:
                    return
                confirm = messagebox.askyesno("Confirm", f"Send {order_type} order for patient {patient_id} with test '{test}'?")
                if confirm:
                    self.send_order(patient_id, name, dob, order_type, test)
            if order_type == "RAD":
                # Prompt for test type choice
                exam = self.get_exam_type()
                if not exam:
                    return
                confirm = messagebox.askyesno("Confirm", f"Send {order_type} order for patient {patient_id} with exam '{exam}'?")
                if confirm:
                    self.send_order(patient_id, name, dob, order_type, exam)
            if order_type == "DOC":
                consultation = self.get_consultation_type()
                if not consultation:
                    return
                confirm = messagebox.askyesno("Confirm", f"Send {order_type} order for patient {patient_id}?")
                if confirm:
                    self.send_order(patient_id, name, dob, order_type, consultation)
        
    def get_test_type(self):
        # Opens a dialog window to choose a lab test type.
        window = tk.Toplevel(self.root)
        window.title("Select Lab Test")
        window.geometry("300x150")
        ttk.Label(window, text="Choose Lab Test:").pack(padx=20, pady=10)
        test_type_var = tk.StringVar()
        types = ["Blood Test", "Cholesterol", "Blood Glucose", "Lipid"]
        combo = ttk.Combobox(window, textvariable=test_type_var, values=types, state="readonly")
        combo.pack(padx=20, pady=10)
        combo.current(0)
    
        def on_confirm():
            window.selected_type = test_type_var.get()
            window.destroy()
    
        ttk.Button(window, text="Confirm", command=on_confirm).pack(pady=10)
        window.wait_window()
        return window.selected_type if hasattr(window, 'selected_type') else None

    def get_exam_type(self):
        # Opens a dialog window to choose a lab test type.
        window = tk.Toplevel(self.root)
        window.title("Select Radio Exam")
        window.geometry("300x150")
        ttk.Label(window, text="Choose Radio Exam:").pack(padx=20, pady=10)
        test_type_var = tk.StringVar()
        types = ["Brain CT"]
        combo = ttk.Combobox(window, textvariable=test_type_var, values=types, state="readonly")
        combo.pack(padx=20, pady=10)
        combo.current(0)
    
        def on_confirm():
            window.selected_type = test_type_var.get()
            window.destroy()
    
        ttk.Button(window, text="Confirm", command=on_confirm).pack(pady=10)
        window.wait_window()
        return window.selected_type if hasattr(window, 'selected_type') else None
    
    def get_consultation_type(self):
        # Opens a dialog window to choose a lab test type.
        window = tk.Toplevel(self.root)
        window.title("Consultation type")
        window.geometry("300x150")
        ttk.Label(window, text="Choose a consultation type:").pack(padx=20, pady=10)
        test_type_var = tk.StringVar()
        types = ["General Consultation", "Urgent Care Consultation"]
        combo = ttk.Combobox(window, textvariable=test_type_var, values=types, state="readonly")
        combo.pack(padx=20, pady=10)
        combo.current(0)
    
        def on_confirm():
            window.selected_type = test_type_var.get()
            window.destroy()
    
        ttk.Button(window, text="Confirm", command=on_confirm).pack(pady=10)
        window.wait_window()
        return window.selected_type if hasattr(window, 'selected_type') else None
    
    def send_hl7(self, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((IPS["EMR"]["ip"], IPS["EMR"]["port"]))
                if ENCRYPTION:   
                    s.sendall(security.encrypt_message(message).encode())
                else:
                    s.sendall(message.encode())
                rec_msg = s.recv(4096).decode()
                if DECRYPTION:
                    return security.decrypt_message(rec_msg)
                else:
                    return rec_msg
        except Exception as e:
            raise ConnectionError(f"HL7 Error: {str(e)}")
    
    def parse_query_response(self, response):
        """
        A simple parser that extracts patient info from PID segments.
        """
        patients = []
        for line in response.split("\r"):
            if line.startswith("PID"):
                fields = line.split("|")
                patients.append({
                    "id": fields[3] if len(fields) > 3 else "",
                    "name": fields[5] if len(fields) > 5 else "",
                    "dob": fields[7] if len(fields) > 7 else "",
                    "phone": fields[13] if len(fields) > 13 else ""
                })
        return patients
    
    def send_removal(self, patient_id):
        # Build HL7 ADT^A03 message.
        try:
            msg = Message("ADT_A03")
            msg.msh.msh_2 = "^~\\&"
            msg.msh.msh_3 = "FRD"
            msg.msh.msh_5 = "EMR"
            msg.msh.msh_9 = "ADT^A03"
            msg.msh.msh_10 = str(uuid.uuid4())
            msg.msh.msh_12 = "2.5"
            pid = msg.add_segment("PID")
            pid.pid_3 = patient_id
            hl7_message = msg.to_er7().replace("\n", "\r") + "\r"
            ack = self.send_hl7(hl7_message)
            if "AA" in ack:
                messagebox.showinfo("Success", "Patient removed")
            else:
                messagebox.showerror("Error", "Removal failed")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def send_order(self, patient_id, name, dob, order_type, subject=None):
        # Build HL7 ORM^O01 message for booking an order.
        try:
            msg = Message("ORM_O01")
            msg.msh.msh_2 = "^~\\&"
            msg.msh.msh_3 = "FRD"
            msg.msh.msh_5 = "EMR"
            msg.msh.msh_9 = "ORM^O01"
            msg.msh.msh_10 = str(uuid.uuid4())
            msg.msh.msh_12 = "2.5"

            pid = msg.add_segment("PID")
            pid.pid_3 = patient_id
            pid.pid_5 = name
            pid.pid_7 = dob
            
            orc = msg.add_segment("ORC")
            orc.orc_1 = "NW"
            orc.orc_2 = f"{order_type}-{uuid.uuid4().hex[:8]}"

            subject_dic = {'Blood Test': 'CBC', 'Cholesterol': 'CHO', 'Blood Glucose': 'GLU', 'Lipid': 'LIP', 
                           "Brain CT": "BCT", 
                           "General Consultation": 'GCO', "Urgent Care Consultation": "UCC"}

            if subject not in subject_dic:
                messagebox.showerror("Error", "Invalid subject selected.")
                return
            
            obr = msg.add_segment("OBR")
            obr.obr_4 = order_type + "-" + subject_dic[subject]

            hl7_message = msg.to_er7().replace("\n", "\r") + "\r"
            ack = self.send_hl7(hl7_message)
            if "AA" in ack:
                messagebox.showinfo("Success", f"{order_type} order created")
            else:
                messagebox.showerror("Error", f"Order failed: {ack}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    AuthWindow(root)
    root.mainloop()
