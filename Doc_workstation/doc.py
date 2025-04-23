# doctor_workstation.py
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import requests
import uuid
from hl7apy.core import Message, Segment
from hl7apy.parser import parse_message
import pydicom
from io import BytesIO
from pydicom import Dataset
from pynetdicom import AE
from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind
from cryptography.fernet import Fernet
from pydicom.pixel_data_handlers.util import apply_voi_lut
from PIL import Image, ImageTk
from datetime import datetime
import hashlib

import security

# Security CONFIG
AUTH_SERVER_URL = "http://172.31.13.200:5001/api/auth"
DIGITAL_SIGNATURE = True
TWO_FA = True
ENCRYPTION = True
DECRYPTION = True

# NETWORK CONFIG
IPS = {
    "PACS":{"ip": "172.31.7.195", "port_dicom": 11112, "port_getfile": 22222},
    "EMR" :{"ip": "172.31.25.176", "port": 2575},
    "AI": {"ip": "172.31.7.185", "port": 22222}
}


# HELPER FUNCTIONS
def parse_time_stamp(timestamp, precision='sec'):
    display_time = timestamp[:4] + '-' + timestamp[4:6] + '-' + timestamp[6:8]
    if precision == 'day':
        return display_time
    elif precision == 'hr':
        return display_time + " " + timestamp[8:10] + 'hr'
    elif precision == "min":
        return display_time + " " + timestamp[8:10] + 'hr ' + timestamp[10:12] + 'min'
    else:
        return display_time + " " + timestamp[8:10] + 'hr ' + timestamp[10:12] + 'min ' + timestamp[12:] + 'sec'
    
class AuthWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Doctor Workstation - Authentication")
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
        self.root.title("Doctor Workstation")
        self.root.geometry("1000x600")
        self.setup_ui()
        self.root.mainloop()
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Button(main_frame, text="View Schedule", command=self.view_schedule).pack(pady=10)

    def view_schedule(self):
        window = tk.Toplevel(self.root)
        window.title("Consultation Schedule")
        window.geometry("900x500")
        
        filter_frame = ttk.Frame(window)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Patient ID:").pack(side=tk.LEFT)
        patient_id_filter = ttk.Entry(filter_frame)
        patient_id_filter.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Consultation Type:").pack(side=tk.LEFT, padx=10)
        consult_type_var = tk.StringVar()
        consult_types = ["General Consultation", "Urgent Care Consultation"]
        consult_combo = ttk.Combobox(filter_frame, textvariable=consult_type_var, values=consult_types, state="readonly")
        consult_combo.pack(side=tk.LEFT)
        consult_combo.current(0)
        
        tree = ttk.Treeview(window, columns=("OrderID", "PatientID", "Name", "DOB", "Consultation", "Booked At"), show="headings")
        tree.heading("OrderID", text="Order ID")
        tree.heading("PatientID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="Date of Birth")
        tree.heading("Consultation", text="Type")
        tree.heading("Booked At", text="Booked At")
        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        def load_data():
            try:
                msg = Message("QRY_A19")
                msg.msh.msh_2 = "^~\\&"
                msg.msh.msh_3 = "DOC"
                msg.msh.msh_5 = "EMR"
                msg.msh.msh_9 = "QRY^A19"
                msg.msh.msh_10 = str(uuid.uuid4())
                msg.msh.msh_12 = "2.5"
                
                qrd = msg.add_segment("QRD")
                qrd.qrd_7 = "-1"
                qrd.qrd_9 = "CLN"
                
                qrf = msg.add_segment("QRF")
                qrf.qrf_1 = "DOC_SCH"
                
                hl7_query = msg.to_er7().replace("\n", "\r")
                response = self.send_hl7(hl7_query)
                consultations = self.parse_consultation_response(response)
                
                for i in tree.get_children():
                    tree.delete(i)
                
                for consult in consultations:
                    tree.insert("", "end", values=(
                        consult["order_id"],
                        consult["patient_id"],
                        consult["name"],
                        consult["dob"],
                        consult["consultation"],
                        consult["booked_at"]
                    ))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load schedule: {str(e)}")
        
        load_data()
        
        menu = tk.Menu(window, tearoff=0)
        menu.add_command(label="Clinic Info", command=lambda: self.show_clinic_info(tree))
        menu.add_command(label="Write Comment", command=lambda: self.write_comment(tree))
        menu.add_command(label="Mark Complete", command=lambda: self.mark_complete(tree))
        menu.add_command(label="View Exams", command=lambda: self.view_patient_exams(tree))
        
        def on_right_click(event):
            iid = tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid)
                menu.post(event.x_root, event.y_root)
        
        tree.bind("<Button-3>", on_right_click)

    def parse_consultation_response(self, response):
        consultations = []
        for line in response.split("\r"):
            if line.startswith("PID"):
                fields = line.split("|")
                consultations.append({
                    "patient_id": fields[3],
                    "name": fields[5],
                    "dob": fields[7],
                    "order_id": fields[18] if len(fields) > 18 else "",
                    "consultation": fields[19] if len(fields) > 19 else "",
                    "booked_at": fields[20] if len(fields) > 20 else ""
                })
        return consultations

    def show_clinic_info(self, tree):
        selected = tree.selection()
        if not selected:
            return
        patient_id = tree.item(selected[0])["values"][1]
        
        try:
            msg = Message("QRY_A19")
            msg.msh.msh_2 = "^~\\&"
            msg.msh.msh_3 = "DOC"
            msg.msh.msh_5 = "EMR"
            msg.msh.msh_9 = "QRY^A19"
            msg.msh.msh_10 = str(uuid.uuid4())
            msg.msh.msh_12 = "2.5"
            
            qrd = msg.add_segment("QRD")
            qrd.qrd_7 = "1"
            qrd.qrd_8 = patient_id
            qrd.qrd_9 = "CLN"
            
            response = self.send_hl7(msg.to_er7().replace("\n", "\r"))
            patient_info = self.parse_patient_response(response)
            
            info_window = tk.Toplevel(self.root)
            info_window.title("Patient Info")
            label_text = (
                            f"Name: {patient_info['name']}\n"
                            f"DOB: {patient_info['dob']}\n"
                            f"Test Record: {patient_info['test_result']}\n"
                            f"Comments: {patient_info['comment']}"
                        )
            ttk.Label(info_window, text=label_text).pack(padx=20, pady=20)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def write_comment(self, tree):
        selected = tree.selection()
        if not selected:
            return
        patient_id = tree.item(selected[0])["values"][1]
        
        comment = simpledialog.askstring("Add Comment", "Enter your comment:")
        if comment:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            cmt_time = parse_time_stamp(timestamp, precision='day')
            formatted_comment = f"CMTtime: {cmt_time.replace('\n', '\r')}; {comment.replace('\n', '\r')}"
            
            try:
                msg = Message("ORU_R01")
                msg.msh.msh_2 = "^~\\&"
                msg.msh.msh_3 = "DOC"
                msg.msh.msh_5 = "EMR"
                msg.msh.msh_9 = "ORU^R01"
                msg.msh.msh_10 = str(uuid.uuid4())
                msg.msh.msh_12 = "2.5"
                
                pid = msg.add_segment("PID")
                pid.pid_3 = patient_id
                
                obx = msg.add_segment("OBX")
                obx.obx_2 = "TX"
                obx.obx_5 = formatted_comment
                
                self.send_hl7(msg.to_er7().replace("\n", "\r"))
                messagebox.showinfo("Success", "Comment added")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def mark_complete(self, tree):
        selected = tree.selection()
        if not selected:
            return
        order_id = tree.item(selected[0])["values"][0]
        
        try:
            msg = Message("ORM_O01")
            msg.msh.msh_2 = "^~\\&"
            msg.msh.msh_3 = "DOC"
            msg.msh.msh_5 = "EMR"
            msg.msh.msh_9 = "ORM^O01"
            msg.msh.msh_10 = str(uuid.uuid4())
            msg.msh.msh_12 = "2.5"
            
            orc = msg.add_segment("ORC")
            orc.orc_1 = "SC"
            orc.orc_2 = order_id
            
            self.send_hl7(msg.to_er7().replace("\n", "\r"))
            messagebox.showinfo("Success", "Status updated")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def view_patient_exams(self, tree):
        """Right-click option to view exams linked to the selected patient."""
        selected = tree.selection()
        if not selected:
            return
        patient_id = tree.item(selected[0])["values"][1]
        exam_records = self.query_all_exams_for_patient(patient_id)
        if not exam_records:
            messagebox.showinfo("No Exams", "No exam records found for this patient.")
            return
        
        exam_window = tk.Toplevel(self.root)
        exam_window.title(f"Exam Records for Patient: {patient_id}")
        exam_window.geometry("800x400")
        
        columns = ("PatientID", "PatientName", "DOB", "InstanceUID")
        exam_tree = ttk.Treeview(exam_window, columns=columns, show="headings")
        for col in columns:
            exam_tree.heading(col, text=col)
            exam_tree.column(col, width=150, anchor="center")
        exam_tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        for ds in exam_records:
            pid = ds.get("PatientID", "N/A")
            pname = ds.get("PatientName", "N/A")
            dob = ds.get("PatientBirthDate", "N/A")
            instance_uid = ds.get("SOPInstanceUID", "N/A")
            exam_tree.insert("", "end", values=(pid, pname, dob, instance_uid))
        
        btn_frame = ttk.Frame(exam_window)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="View Selected Image", command=lambda: self.view_exam_image(exam_tree, exam_window)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Send Dicom to AI", command=lambda: self.send_exam_to_ai(exam_tree)).pack(side=tk.LEFT, padx=5)

    def query_all_exams_for_patient(self, patient_id):      
        ae = AE()
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
        assoc = ae.associate(IPS["PACS"]["ip"], IPS["PACS"]["port_dicom"], ae_title="PACS")
        if not assoc.is_established:
            messagebox.showerror("DICOM Association Failed", "Unable to establish association with PACS for query.")
            return []
        
        ds = Dataset()
        ds.QueryRetrieveLevel = "PATIENT"
        ds.PatientID = patient_id
        exam_records = []
        responses = assoc.send_c_find(ds, PatientRootQueryRetrieveInformationModelFind)
        for (status, identifier) in responses:
            if status and identifier:
                exam_records.append(identifier)
        assoc.release()
        return exam_records

    def view_exam_image(self, exam_tree, parent_window):
        selected = exam_tree.selection()
        if not selected:
            messagebox.showerror("Selection Error", "Please select an exam record to view.")
            return
        item = exam_tree.item(selected[0])
        instance_uid = item["values"][3]
        ds = self.retrieve_file_from_pacs(instance_uid)
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
            try:
                arr = apply_voi_lut(ds.pixel_array, ds)
                arr = arr - arr.min()
                if arr.max() > 0:
                    arr = (arr / arr.max() * 255).astype('uint8')
                img = Image.fromarray(arr)
            except Exception as e:
                messagebox.showerror("Image Extraction Error", f"Failed to extract image: {e}")
                return
            img_window = tk.Toplevel(parent_window)
            img_window.title(f"Image for Instance {instance_uid}")
            photo = ImageTk.PhotoImage(img)
            label = ttk.Label(img_window, image=photo)
            label.image = photo
            label.pack()
        else:
            messagebox.showerror("Signature validation failed")

    def send_exam_to_ai(self, exam_tree):
        selected = exam_tree.selection()
        if not selected:
            messagebox.showerror("Selection Error", "Please select an exam record.")
            return
        item = exam_tree.item(selected[0])
        instance_uid = item["values"][3]
        ds = self.retrieve_file_from_pacs(instance_uid)
        if ds is None:
            return
        try:
            buffer = BytesIO()
            ds.save_as(buffer, write_like_original=False)
            dicom_bytes = buffer.getvalue()
        except Exception as e:
            messagebox.showerror("DICOM Save Error", f"Failed to save DICOM file: {e}")
            return
        try:
            ai_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ai_sock.settimeout(10)
            ai_sock.connect((IPS["AI"]["ip"], IPS["AI"]["port"]))
            ai_sock.sendall(dicom_bytes)
            ai_sock.shutdown(socket.SHUT_WR)
            
            result = b""
            while True:
                try:
                    chunk = ai_sock.recv(4096)
                    if not chunk:
                        break
                    result += chunk
                except socket.timeout:
                    break
            ai_sock.close()
            
            if result:
                result_str = result.decode("utf-8")
                messagebox.showinfo("AI Analysis Result: ", result_str)
            else:
                messagebox.showinfo("Success", "DICOM file sent to AI server successfully, but no result was returned.")
        except Exception as e:
            messagebox.showerror("AI Server Error", f"Failed to send DICOM file to AI server: {e}")

    def retrieve_file_from_pacs(self, instance_uid):
        """Retrieve the encrypted DICOM file from PACS using a socket connection."""
        file_name = f"{instance_uid}.dcm.enc"
        if ENCRYPTION:
            file_name = security.encrypt_message(file_name.encode())
        else:
            file_name = file_name.encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IPS["PACS"]["ip"], IPS["PACS"]["port_getfile"]))
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

    def send_hl7(self, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((IPS["EMR"]["ip"], IPS["EMR"]["port"]))
                if ENCRYPTION:
                    message = security.encrypt_message(message)
                s.sendall(message.encode())
                if DECRYPTION:
                    return security.decrypt_message(s.recv(4096).decode())
                else:
                    return (s.recv(4096).decode())
        except Exception as e:
            raise ConnectionError(f"HL7 Error: {str(e)}")

    def parse_patient_response(self, response):
        patient = {}
        for line in response.split("\r"):
            if line.startswith("PID"):
                fields = line.split("|")
                patient = {
                    "id": fields[3],
                    "name": fields[5],
                    "dob": fields[7],
                }
                patient["ssn"] = fields[19] if len(fields) >= 19 else ''
                patient["phone"] = fields[13] if len(fields) >= 13 else ''
            if line.startswith("OBX"):
                fields = line.split("|")
                tests = fields[5]
                patient["test_result"] = '\n' + tests.replace("##", '\n')
            if line.startswith("NTE"):
                fields = line.split("|")
                comments = fields[3]
                patient["comment"] = '\n' + comments.replace("##", '\n')
                print(patient["comment"])

        return patient

if __name__ == "__main__":
    root = tk.Tk()
    AuthWindow(root)
    root.mainloop()