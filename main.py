import tkinter as tk
from tkinter import filedialog, messagebox
import yara
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pdfminer.high_level import extract_text
import os

class MalwareMonitorApp:
    EMAIL_HOST = 'smtp.example.com'
        EMAIL_PORT = 587
        EMAIL_HOST_USER = 'your-email@example.com'
        EMAIL_HOST_PASSWORD = 'your-password'
        EMAIL_FROM = 'your-email@example.com'
        EMAIL_TO = 'recipient@example.com'
        
    
    def __init__(self, root):
        self.root = root
        self.root.title("Malware Monitor")
        
        self.label = tk.Label(root, text="Select a file to analyze:")
        self.label.pack(pady=10)
        
        self.select_button = tk.Button(root, text="Select File", command=self.select_file)
        self.select_button.pack(pady=10)
        
        self.result_text = tk.Text(root, height=10, width=50)
        self.result_text.pack(pady=10)
        
        self.analyze_button = tk.Button(root, text="Analyze", command=self.analyze_file)
        self.analyze_button.pack(pady=10)
        
        self.filepath = None
    
    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.result_text.delete(1.0, tk.END)
            filename = os.path.basename(self.filepath)
            self.result_text.insert(tk.END, f"Selected file: {filename}\n")
    
    def analyze_file(self):
        if not self.filepath:
            messagebox.showwarning("Warning", "No file selected!")
            return
        
        try:
            matches = None
            filename = os.path.basename(self.filepath)

            if self.filepath.endswith('.pdf'):
                matches = self.analyze_pdf(self.filepath)
            else:
                rules = yara.compile(filepath='test_malware_pdf.yar')
                matches = rules.match(self.filepath)
            
            if matches and len(matches) > 0:
                result = f"Malware detected in file: {filename}"
                messagebox.showinfo("Analysis Result", f"Malware detected in file: {filename}")
                self.send_email("Malware detected", f"Warning: The file '{filename}' is malicious. Please be cerfull !")
            else:
                result = f"No malware detected in file: {filename}"
                messagebox.showinfo("Analysis Result", f"No malware detected in file: {filename}")
            
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result)
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def analyze_pdf(self, filepath):
        try:
            text = extract_text(filepath)
            with open("temp_text.txt", "w") as temp_file:
                temp_file.write(text)
            
            rules = yara.compile(filepath='test_malware_pdf.yar')
            matches = rules.match("temp_text.txt")
            return matches
        except Exception as e:
            print(f"Error analyzing PDF: {str(e)}")
            return None
    
    def send_email(self, subject, body):
        message = MIMEMultipart()
        message['From'] = self.EMAIL_FROM
        message['To'] = self.EMAIL_TO
        message['Subject'] = subject
        
        message.attach(MIMEText(body, 'plain'))
        
        try:
            with smtplib.SMTP(self.EMAIL_HOST, self.EMAIL_PORT) as server:
                server.starttls()
                server.login(self.EMAIL_HOST_USER, self.EMAIL_HOST_PASSWORD)
                server.send_message(message)
                print("Email sent successfully!")
        except Exception as e:
            print(f"Error sending email: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareMonitorApp(root)
    root.mainloop()
