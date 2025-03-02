import socket
import ssl
import os
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from dotenv import load_dotenv
import tkinter as tk
from tkinter import scrolledtext

# Načítanie hodnôt zo súboru .env
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY').encode('utf-8')
HOST = os.getenv('HOST', '0.0.0.0')
PORT = os.getenv('PORT')
if PORT is None:
    raise Exception("PORT is missing in environment variables")
PORT = int(PORT)

CERT_PATH = os.getenv('CERT_PATH', 'server_cert.pem')
KEY_PATH = os.getenv('KEY_PATH', 'server_key.pem')
CERT_PASSPHRASE = os.getenv('CERT_PASSPHRASE', '').encode('utf-8')

clients = []

class ChatServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Chat Server")
        self.root.geometry("735x480")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, font=("Monospace", 10))
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Tlačidlo na spustenie servera
        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack(padx=5, pady=5)

        # Tlačidlo na zastavenie servera
        self.stop_button = tk.Button(root, text="Stop Server", command=self.stop_server)
        self.stop_button.pack(padx=5, pady=5)
        self.stop_button.pack_forget()  # Skryjeme stop button pri štarte

        self.status_label = tk.Label(root, text="Server not running", font=("Arial", 12))
        self.status_label.pack(padx=5, pady=5)

        self.server_thread = None
        self.server_socket = None
        self.running = False

    def display_message(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

    def encrypt_ip(self, ip):
        cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
        ip_padded = pad(ip.encode('utf-8'), AES.block_size)
        encrypted_ip = cipher.encrypt(ip_padded)
        return base64.b64encode(encrypted_ip).decode('utf-8')

    def handle_client(self, secure_socket, client_address):
        client_public_key = secure_socket.recv(2048)
        aes_key = self.load_key()
        encrypted_aes_key = self.encrypt_aes_key_with_rsa(aes_key, client_public_key)
        secure_socket.send(encrypted_aes_key)

        encrypted_ip = self.encrypt_ip(client_address[0])

        name_msg = secure_socket.recv(1024).decode('utf-8')
        if name_msg.startswith("TEXT:"):
            name = name_msg[5:]
        else:
            name = name_msg
        self.display_message(f"Pripojený klient: {encrypted_ip} ako {name}")
        clients.append((secure_socket, name))

        while self.running:
            try:
                encrypted_message = secure_socket.recv(1024).decode('utf-8')
                if encrypted_message:
                    self.display_message(f"Prijatá šifrovaná správa od {name}: {encrypted_message}")
                    message_with_name = f"{name}:{encrypted_message}"
                    self.broadcast_message(message_with_name, secure_socket)
                else:
                    self.display_message(f"Klient {encrypted_ip} ({name}) odpojil spojenie.")
                    break
            except Exception as e:
                self.display_message(f"Chyba pri spracovaní správy pre klienta {encrypted_ip}: {e}")
                break

        secure_socket.close()
        clients.remove((secure_socket, name))

    def broadcast_message(self, message, exclude_socket):
        for client, client_name in clients:
            if client != exclude_socket:
                client.send(message.encode('utf-8'))
                self.display_message(f"Správa poslaná klientovi {client_name}")

    def start_server(self):
        self.running = True
        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.status_label.config(text="Server running...")

        # Skryjeme tlačidlo "Start" a ukážeme "Stop"
        self.start_button.pack_forget()
        self.stop_button.pack()

    def run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(5)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH, password=CERT_PASSPHRASE)

        self.generate_and_save_key()

        self.display_message("Server čaká na pripojenie...")

        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                secure_socket = context.wrap_socket(client_socket, server_side=True)
                threading.Thread(target=self.handle_client, args=(secure_socket, client_address)).start()
        except KeyboardInterrupt:
            self.display_message("\nServer bol úspešne ukončený.")
        finally:
            self.server_socket.close()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join()  # Wait for the server thread to finish
        self.status_label.config(text="Server stopped.")

        # Skryjeme tlačidlo "Stop" a ukážeme "Start"
        self.stop_button.pack_forget()
        self.start_button.pack()

    def generate_and_save_key(self):
        key = get_random_bytes(32)
        with open("aes_key.bin", "wb") as f:
            f.write(key)
        return key

    def load_key(self):
        if not os.path.exists("aes_key.bin"):
            return self.generate_and_save_key()
        with open("aes_key.bin", "rb") as f:
            return f.read()

    def encrypt_aes_key_with_rsa(self, aes_key, client_public_key):
        rsa_key = RSA.import_key(client_public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        return encrypted_aes_key


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatServerApp(root)
    root.mainloop()
