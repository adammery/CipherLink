import socket
import ssl
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
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

        # Univerzálne získanie IP a portu
        self.host, self.port = self.choose_or_enter_server()

        # Inicializácia UI
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

    def display_message(self, message):
        self.text_area.configure(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.configure(state=tk.DISABLED)

    def load_rsa_keys(self):
        try:
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            return private_key, public_key
        except Exception as e:
            self.display_message(f"System: Error loading RSA keys - {str(e)}")
            sys.exit()

    def choose_or_enter_server(self):
        servers = self.load_server_settings()

        dialog = tk.Toplevel(self.root)
        dialog.title("Server Settings")

        tk.Label(dialog, text="Select a server or enter a new one:").pack(padx=10, pady=10)
        server_list = ttk.Combobox(dialog, values=servers, width=40)
        server_list.pack(padx=10, pady=5)
        server_list.set("Enter new server")

        tk.Label(dialog, text="IP Address:").pack(padx=10, pady=5)
        ip_entry = tk.Entry(dialog, width=30)
        ip_entry.pack(padx=10, pady=5)

        tk.Label(dialog, text="Port:").pack(padx=10, pady=5)
        port_entry = tk.Entry(dialog, width=30)
        port_entry.pack(padx=10, pady=5)

        def submit():
            selected = server_list.get()
            if selected and selected != "Enter new server":
                ip, port = selected.split(":")
                port = int(port)
            else:
                ip = ip_entry.get().strip()
                port = port_entry.get().strip()
                try:
                    port = int(port)
                except ValueError:
                    messagebox.showerror("Error", "Port must be a number!")
                    return
            dialog.result = (ip, port)
            dialog.destroy()

        submit_button = tk.Button(dialog, text="Connect", command=submit)
        submit_button.pack(pady=10)

        dialog.wait_window()
        return dialog.result
    
    def is_server_saved(self):
        settings_path = os.path.join(os.path.dirname(__file__), "chat_client_settings.txt")
        if os.path.exists(settings_path):
            with open(settings_path, "r") as file:
                saved_servers = file.readlines()
                current_server = f"{self.host}:{self.port}\n"
                return current_server in saved_servers
        return False

    def load_server_settings(self):
        settings_path = os.path.join(os.path.dirname(__file__), "chat_client_settings.txt")
        if os.path.exists(settings_path):
            with open(settings_path, "r") as file:
                return [line.strip() for line in file.readlines() if ":" in line]
        return []

    def save_server_settings(self):
        settings_path = os.path.join(os.path.dirname(__file__), "chat_client_settings.txt")
        try:
            with open(settings_path, "a") as file:
                file.write(f"{self.host}:{self.port}\n")
            self.display_message("System: Server settings saved successfully!")
        except Exception as e:
            self.display_message(f"System: Error saving server settings - {str(e)}")

    def setup_connection(self):
        try:
            self.display_message(f"System: Connecting to {self.host}:{self.port}...")
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.secure_socket = context.wrap_socket(client_socket, server_hostname=self.host)
            self.secure_socket.connect((self.host, self.port))
            self.display_message(f"System: Successfully connected to {self.host}:{self.port}")

            # Odoslanie verejného kľúča a prijatie AES kľúča
            self.secure_socket.send(self.public_key.export_key())
            encrypted_aes_key = self.secure_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            self.user_name = simpledialog.askstring("Name", "Enter your name:")
            self.secure_socket.send(f"TEXT:{self.user_name}".encode('utf-8'))
            self.display_message(f"System: {self.user_name} joined the chat.")

            # Kontrola, či server už je uložený
            if not self.is_server_saved():
                self.show_save_server_dialog()

        except Exception as e:
            self.display_message(f"System: Connection error - {str(e)}")

    def show_save_server_dialog(self):
        """Displays a dialog to save the server."""
        save_dialog = tk.Toplevel(self.root)
        save_dialog.title("Save Server")

        tk.Label(save_dialog, text="Do you want to save this server?").pack(padx=20, pady=10)

        def save_server():
            self.save_server_settings()
            save_dialog.destroy()

        def do_not_save_server():
            self.display_message("System: Server was not saved.")
            save_dialog.destroy()

        save_button = tk.Button(save_dialog, text="Save", command=save_server)
        save_button.pack(side=tk.LEFT, padx=10, pady=10)

        cancel_button = tk.Button(save_dialog, text="Don't Save", command=do_not_save_server)
        cancel_button.pack(side=tk.RIGHT, padx=10, pady=10)

    # Zvyšné metódy ostávajú nezmenené

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

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        nonce = cipher.nonce
        return base64.urlsafe_b64encode(nonce + tag + ciphertext).decode('utf-8')

    def send_message(self, event=None):
        message = self.entry.get().strip()
        if not message:  # Ak je správa prázdna, nevykonáme nič
            return

        current_time = time.time()
        if current_time - self.last_message_time < 1:  # 1 sekundy medzi správami
            self.display_message("System: You're sending messages too quickly!")
            return

        encrypted_message = self.encrypt_message(message)
        self.secure_socket.send(encrypted_message.encode('utf-8'))
        self.entry.delete(0, tk.END)
        self.display_message(f"Me: {message}")
        self.last_message_time = current_time


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
