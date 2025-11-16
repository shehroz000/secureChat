
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Fork this repository** to your own GitHub account (using official nu email).  
   All development and commits must be performed in your fork.

2. **Set up environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   Create a `.env` file with the following (or use the provided template):
   ```bash
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=securechat
   DB_USER=scuser
   DB_PASSWORD=scpass

   # Server Configuration
   SERVER_HOST=localhost
   SERVER_PORT=8888

   # Certificate Paths
   CA_CERT_PATH=certs/ca.crt
   CA_KEY_PATH=certs/ca.key
   SERVER_CERT_PATH=certs/server.crt
   SERVER_KEY_PATH=certs/server.key
   CLIENT_CERT_PATH=certs/client.crt
   CLIENT_KEY_PATH=certs/client.key
   ```

4. **Initialize MySQL** (recommended via Docker):
   ```bash
   docker run -d --name securechat-db \
     -e MYSQL_ROOT_PASSWORD=rootpass \
     -e MYSQL_DATABASE=securechat \
     -e MYSQL_USER=scuser \
     -e MYSQL_PASSWORD=scpass \
     -p 3306:3306 mysql:8
   ```

5. **Create database tables**:
   ```bash
   python -m app.storage.db --init
   ```

6. **Generate certificates**:
   ```bash
   # Generate Root CA
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   
   # Generate server certificate
   python scripts/gen_cert.py --cn server.local --out certs/server
   
   # Generate client certificate
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

7. **Run the server** (in one terminal):
   ```bash
   source .venv/bin/activate
   python -m app.server
   ```

8. **Run the client** (in another terminal):
   ```bash
   source .venv/bin/activate
   python -m app.client
   ```

## 📝 Usage

### Server
The server listens on `localhost:8888` by default. It will:
- Accept client connections
- Perform mutual certificate authentication
- Handle user registration and login
- Establish encrypted chat sessions
- Maintain session transcripts

### Client
The client connects to the server and prompts for:
- **Registration or Login**: Choose 'r' to register or 'l' to login
- **Credentials**: Email, username (for registration), and password
- **Chat**: Type messages to send. Type 'quit' to end the session

### Sample Session Flow
1. Client connects and sends certificate
2. Server validates client certificate and sends its own
3. Client validates server certificate
4. Diffie-Hellman key exchange for authentication encryption
5. Client sends encrypted registration/login credentials
6. Server verifies and authenticates user
7. New Diffie-Hellman exchange for chat session key
8. Encrypted, signed messages exchanged
9. Session receipt generated and exchanged on termination

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 🧪 Test Evidence Checklist

### Wireshark Capture
1. **Install Wireshark**: 
   - macOS: `brew install --cask wireshark`
   - Or download from https://www.wireshark.org/download.html

2. **Start Capture**:
   - Open Wireshark
   - Select interface: `lo0` (loopback) or `any`
   - Set display filter: `tcp.port == 8888`
   - Click Start (blue shark fin icon)

3. **Run Chat Session**:
   - Start server: `python -m app.server`
   - Start client: `python -m app.client`
   - Register/login and send messages

4. **Verify Encryption**:
   - Check that no plaintext passwords are visible
   - Verify chat messages show only base64-encoded ciphertext
   - Look for JSON structure with `encrypted`, `ct`, `sig` fields
   - See detailed guide in `WIRESHARK_GUIDE.md`

**Alternative (Command Line)**:
```bash
# Capture to file
sudo tcpdump -i lo0 -w capture.pcap port 8888
# Then open capture.pcap in Wireshark
```

### Certificate Validation Tests
- **Invalid Certificate**: Modify a certificate file and verify `BAD_CERT` error
- **Expired Certificate**: Create an expired cert and verify rejection
- **Self-Signed Certificate**: Try connecting with a self-signed cert (not signed by CA)

### Tamper Test
1. Capture a message in Wireshark
2. Modify a bit in the ciphertext
3. Replay the modified message
4. Verify server rejects with `SIG_FAIL` error

### Replay Test
1. Capture a valid message
2. Replay the same message (same seqno)
3. Verify server rejects with `REPLAY` error

### Non-Repudiation
1. Complete a chat session
2. Check `transcripts/` directory for session transcript
3. Verify SessionReceipt is generated and signed
4. Offline verification:
   - Recompute transcript hash: `SHA256(transcript_lines)`
   - Verify receipt signature using certificate public key
   - Verify each message signature in transcript

## 🔒 Security Features Implemented

### Confidentiality
- AES-128 encryption for all chat messages
- Diffie-Hellman key exchange for session key establishment
- Credentials encrypted during authentication phase

### Integrity
- SHA-256 hashing of message metadata (seqno || timestamp || ciphertext)
- RSA signatures on all messages
- Signature verification on message receipt

### Authenticity
- X.509 certificate-based mutual authentication
- Certificate validation (CA signature, expiry, CN matching)
- RSA signatures prove message origin

### Non-Repudiation
- Append-only session transcripts
- Signed SessionReceipt with transcript hash
- Offline verifiable evidence of communication

## 📚 Implementation Details

### Cryptographic Primitives
- **AES-128**: ECB mode with PKCS#7 padding (via `cryptography` library)
- **RSA**: 2048-bit keys, PKCS#1 v1.5 padding, SHA-256 hashing
- **Diffie-Hellman**: Standard MODP group, session key derived as `Trunc16(SHA256(Ks))`
- **SHA-256**: For password hashing, message digests, and transcript hashing

### Protocol Phases
1. **Control Plane**: Certificate exchange and validation
2. **Key Agreement (Auth)**: DH exchange for credential encryption
3. **Authentication**: Encrypted registration/login
4. **Key Agreement (Session)**: New DH exchange for chat encryption
5. **Data Plane**: Encrypted, signed message exchange
6. **Non-Repudiation**: Session receipt generation and exchange

### Database Schema
```sql
CREATE TABLE users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (username),
    INDEX idx_email (email)
);
```

Password storage: `pwd_hash = hex(SHA256(salt || password))` where salt is 16 random bytes per user.

## ⚠️ Important Notes

- **No TLS/SSL**: All cryptography is implemented at the application layer
- **No Secrets in Git**: Certificates, keys, and `.env` files are gitignored
- **Standard Libraries Only**: Uses `cryptography`, `pymysql`, `pydantic`, `rich` libraries
- **Progressive Commits**: Repository should show ≥10 meaningful commits demonstrating development progress  
