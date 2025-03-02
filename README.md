# CipherLink

CipherLink is an encrypted chat server that allows secure communication between clients over SSL, using AES encryption for messages and RSA for key exchange.

## Requirements

- Python version (e.g., Python 3.10+)
- Dependencies (list any Python libraries, packages, or other tools required for the project)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/adammery/CipherLink.git
  

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

5. Set up environment variables (.env):
    Add the necessary variables to your .env file, for example:
   
    ```bash 
    SECRET_KEY=your_secret_key
    HOST=0.0.0.0
    PORT=your_port
    CERT_PATH=path_to_your_cert.pem
    KEY_PATH=path_to_your_key.pem

7. To start the server:
   ```bash
   python server.py
