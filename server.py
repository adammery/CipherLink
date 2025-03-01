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

def encrypt_ip(ip):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    ip_padded = pad(ip.encode('utf-8'), AES.block_size)
    encrypted_ip = cipher.encrypt(ip_padded)
    return base64.b64encode(encrypted_ip).decode('utf-8')

def decrypt_ip(encrypted_ip):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted_ip_bytes = base64.b64decode(encrypted_ip.encode('utf-8'))
    ip_padded = cipher.decrypt(encrypted_ip_bytes)
    ip = unpad(ip_padded, AES.block_size).decode('utf-8')
    return ip

def generate_and_save_key():
    key = get_random_bytes(32)  # Generuje 256-bitový AES kľúč
    with open("aes_key.bin", "wb") as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists("aes_key.bin"):
        return generate_and_save_key()
    with open("aes_key.bin", "rb") as f:
        return f.read()

def encrypt_aes_key_with_rsa(aes_key, client_public_key):
    rsa_key = RSA.import_key(client_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def handle_client(secure_socket, client_address):
    client_public_key = secure_socket.recv(2048)
    aes_key = load_key()
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, client_public_key)
    secure_socket.send(encrypted_aes_key)  # Poslanie zašifrovaného AES kľúča klientovi

    encrypted_ip = encrypt_ip(client_address[0])

    name_msg = secure_socket.recv(1024).decode('utf-8')
    if name_msg.startswith("TEXT:"):
        name = name_msg[5:]
    else:
        name = name_msg
    print(f"Pripojený klient: {encrypted_ip} ako {name}")

    clients.append((secure_socket, name))

    while True:
        try:
            encrypted_message = secure_socket.recv(1024).decode('utf-8')
            if encrypted_message:
                print(f"Prijatá šifrovaná správa od {name}: {encrypted_message}")

                # Pridanie mena k zašifrovanej správe
                message_with_name = f"{name}:{encrypted_message}"
                print(f"Odosielam správu: {message_with_name}")

                for client, client_name in clients:
                    if client != secure_socket:
                        client.send(message_with_name.encode('utf-8'))
                        print(f"Správa poslaná klientovi {client_name}")

            else:
                print(f"Klient {encrypted_ip} ({name}) odpojil spojenie.")
                break
        except Exception as e:
            print(f"Chyba pri spracovaní správy pre klienta {encrypted_ip}: {e}")
            break

    secure_socket.close()
    clients.remove((secure_socket, name))

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH, password=CERT_PASSPHRASE)

    generate_and_save_key()

    print("Server čaká na pripojenie...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            threading.Thread(target=handle_client, args=(secure_socket, client_address)).start()
    except KeyboardInterrupt:
        print("\nServer bol úspešne ukončený.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
