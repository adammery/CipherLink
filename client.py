import socket
import ssl
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import unicodedata
import threading
import select
import os
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, ttk

class ChatClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Chat")
        self.root.geometry("735x450")
        
        self.host = simpledialog.askstring("Server Settings", "Enter server IP address:")
        self.port = simpledialog.askinteger("Server Settings", "Enter server port:")
        
        if not self.host or not self.port:
            messagebox.showerror("Error", "IP and port are required!")
            sys.exit()

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, font=("Monospace", 10))
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(root, width=70)
        self.entry.pack(padx=10, pady=5, side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(padx=5, pady=5, side=tk.RIGHT)

        self.logout_button = tk.Button(root, text="Logout", command=self.logout)
        self.logout_button.pack(padx=5, pady=5, side=tk.RIGHT)

        self.aes_key = None
        self.secure_socket = None
        self.last_message_time = 0
        self.user_name = None

        self.private_key, self.public_key = self.load_rsa_keys()
        self.setup_connection()

        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def get_key_path(self, filename):
        app_dir = os.path.expanduser("~/Library/Application Support/CipherLink/")
        if not os.path.exists(app_dir):
            os.makedirs(app_dir)
        return os.path.join(app_dir, filename)

    def load_rsa_keys(self):
        private_path = self.get_key_path("private.pem")
        public_path = self.get_key_path("public.pem")

        if not os.path.exists(private_path) or not os.path.exists(public_path):
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            with open(private_path, "wb") as priv_file:
                priv_file.write(private_key)
            with open(public_path, "wb") as pub_file:
                pub_file.write(public_key)

        with open(private_path, "rb") as priv_file:
            private_key = RSA.import_key(priv_file.read())
        with open(public_path, "rb") as pub_file:
            public_key = RSA.import_key(pub_file.read())

        return private_key, public_key

    def setup_connection(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_socket = context.wrap_socket(client_socket, server_hostname=self.host)
        self.secure_socket.connect((self.host, self.port))

        self.secure_socket.send(self.public_key.export_key())
        encrypted_aes_key = self.secure_socket.recv(2048)
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        self.user_name = simpledialog.askstring("Name", "Enter your name:")
        self.secure_socket.send(f"TEXT:{self.user_name}".encode('utf-8'))
        self.display_message(f"System: {self.user_name} joined the chat.")

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        nonce = cipher.nonce
        return base64.urlsafe_b64encode(nonce + tag + ciphertext).decode('utf-8')

    def send_message(self, event=None):
        message = self.entry.get().strip()
        if message:
            encrypted_message = self.encrypt_message(message)
            self.secure_socket.send(encrypted_message.encode('utf-8'))
            self.entry.delete(0, tk.END)
            self.display_message(f"Me: {message}")

    def display_message(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

    def receive_messages(self):
        while True:
            try:
                ready_to_read, _, _ = select.select([self.secure_socket], [], [], 1)
                if ready_to_read:
                    message_with_name = self.secure_socket.recv(2048).decode('utf-8')
                    if message_with_name:
                        name, encrypted_message = message_with_name.split(":", 1)
                        decrypted_response = self.decrypt_message(encrypted_message)
                        self.display_message(f"{name}: {decrypted_response}")
                    else:
                        break
            except Exception as e:
                self.display_message(f"System: Error - {str(e)}")
                break

    def decrypt_message(self, encrypted_message):
        encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
        nonce = encrypted_message_bytes[:16]
        tag = encrypted_message_bytes[16:32]
        ciphertext = encrypted_message_bytes[32:]
        cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def logout(self):
        self.secure_socket.close()
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientApp(root)
    root.mainloop()
