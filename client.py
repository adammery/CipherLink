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

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

def load_rsa_keys():
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        generate_rsa_keys()
    with open("private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    with open("public.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    return private_key, public_key

def decrypt_aes_key(encrypted_aes_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def decrypt_message(encrypted_message, key):
    encrypted_message = encrypted_message + '=' * (-len(encrypted_message) % 4)
    encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
    nonce = encrypted_message_bytes[:16]
    tag = encrypted_message_bytes[16:32]
    ciphertext = encrypted_message_bytes[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return decrypted_message
    except ValueError as e:
        print(f"Dešifrovanie zlyhalo: {e}")
        return None

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    nonce = cipher.nonce
    encrypted_message = base64.urlsafe_b64encode(nonce + tag + ciphertext).decode('utf-8')
    return encrypted_message

def to_ascii(input_str):
    return unicodedata.normalize('NFKD', input_str).encode('ascii', 'ignore').decode('ascii')

def clear_input_line():
    sys.stdout.write('\033[2K\033[1G')  # Vymaž aktuálny riadok

def receive_messages(secure_socket, key):
    while True:
        try:
            ready_to_read, _, _ = select.select([secure_socket], [], [], 1)
            if ready_to_read:
                message_with_name = secure_socket.recv(2048).decode('utf-8')
                if message_with_name:
                    name, encrypted_message = message_with_name.split(":", 1)
                    decrypted_response = decrypt_message(encrypted_message, key)
                    clear_input_line()
                    print(f"\rPrijatá správa od {name}: {decrypted_response}")
                    print("Napíšte správu pre server (pre ukončenie napíšte 'exit'): ", end='', flush=True)
                else:
                    break
        except Exception as e:
            print(f"Chyba pri prijímaní správy: {e}")
            break

def start_client():
    private_key, public_key = load_rsa_keys()

    host = '127.0.0.1'
    port = 12345
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("server_cert.pem")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_socket = context.wrap_socket(client_socket, server_hostname=host)
    secure_socket.connect((host, port))

    secure_socket.send(public_key.export_key())  # Poslanie verejného kľúča serveru
    encrypted_aes_key = secure_socket.recv(2048)
    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

    name = input("Zadajte vaše meno: ")
    name = to_ascii(name)

    secure_socket.send(f"TEXT:{name}".encode('utf-8'))
    print(f"Vaše meno: {name}")

    receive_thread = threading.Thread(target=receive_messages, args=(secure_socket, aes_key))
    receive_thread.start()

    try:
        while True:
            clear_input_line()
            message = input("Napíšte správu (pre ukončenie 'exit'): ")
            message = to_ascii(message)

            if message.lower() == 'exit':
                break

            encrypted_message = encrypt_message(message, aes_key)
            secure_socket.send(encrypted_message.encode('utf-8'))
            clear_input_line()
            print(f"Napíšte správu (pre ukončenie 'exit'): ", end='', flush=True)
    except KeyboardInterrupt:
        print("\nProgram bol úspešne ukončený.")
    finally:
        secure_socket.close()
        print("Spojenie bolo ukončené.")

if __name__ == "__main__":
    start_client()

    
