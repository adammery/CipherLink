# CipherLink

CipherLink is my testing project – an encrypted chat server that enables secure communication between clients over SSL, using AES encryption for messages and RSA for key exchange.

## Requirements

- Python version (e.g., Python 3.10+)
- Dependencies (listed in `requirements.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/adammery/CipherLink.git
   cd CipherLink
  

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

5. Set up environment variables:

   Create a `.env` file and add the necessary variables:
   
    ```bash 
    SECRET_KEY=your_secret_key
    HOST=0.0.0.0
    PORT=your_port
    CERT_PATH=path_to_your_cert.pem
    KEY_PATH=path_to_your_key.pem

7. Start the server:
   ```bash
   python server.py
