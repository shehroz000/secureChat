"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import os
import sys
import json
import socket
import secrets
import hashlib
import threading
from typing import Optional
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from cryptography.hazmat.primitives import serialization

from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt, ErrorMessage
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.aes import encrypt, decrypt
from app.crypto.dh import generate_private_key, compute_public_value, derive_shared_secret, derive_session_key, generate_dh_params
from app.crypto.pki import load_certificate, load_private_key, validate_certificate, get_certificate_fingerprint, load_certificate_from_pem
from app.crypto.sign import sign_with_cert_private_key, verify_with_cert
from app.storage.transcript import Transcript

load_dotenv()
console = Console()


def send_message(sock: socket.socket, message: dict):
    """Send JSON message over socket."""
    data = json.dumps(message).encode('utf-8')
    sock.sendall(data + b'\n')


def receive_message(sock: socket.socket) -> Optional[dict]:
    """Receive JSON message from socket."""
    buffer = b''
    while True:
        data = sock.recv(4096)
        if not data:
            return None
        buffer += data
        if b'\n' in buffer:
            line = buffer.split(b'\n', 1)[0]
            try:
                return json.loads(line.decode('utf-8'))
            except json.JSONDecodeError:
                return None


def main():
    """Main client function."""
    host = os.getenv('SERVER_HOST', 'localhost')
    port = int(os.getenv('SERVER_PORT', 8888))
    
    # Load client certificate and key
    client_cert_path = os.getenv('CLIENT_CERT_PATH', 'certs/client.crt')
    client_key_path = os.getenv('CLIENT_KEY_PATH', 'certs/client.key')
    ca_cert_path = os.getenv('CA_CERT_PATH', 'certs/ca.crt')
    
    if not os.path.exists(client_cert_path) or not os.path.exists(client_key_path):
        console.print("[red]Client certificate or key not found. Please generate certificates first.[/red]")
        return
    
    client_cert = load_certificate(client_cert_path)
    client_key = load_private_key(client_key_path)
    ca_cert = load_certificate(ca_cert_path)
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        console.print(Panel(f"[green]Connected to {host}:{port}[/green]", title="Client"))
    except Exception as e:
        console.print(f"[red]Connection failed: {e}[/red]")
        return
    
    try:
        # Phase 1: Control Plane - Certificate Exchange
        # Send client hello
        client_nonce = secrets.token_bytes(16)
        hello = HelloMessage(
            client_cert=client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            nonce=b64e(client_nonce)
        )
        send_message(sock, hello.model_dump())
        console.print("[cyan]Sent client hello[/cyan]")
        
        # Receive server hello
        server_hello_data = receive_message(sock)
        if not server_hello_data or server_hello_data.get('type') != 'server_hello':
            console.print("[red]Invalid server hello[/red]")
            return
        
        server_hello = ServerHelloMessage(**server_hello_data)
        server_cert = load_certificate_from_pem(server_hello.server_cert)
        
        # Validate server certificate
        is_valid, error = validate_certificate(server_cert, ca_cert, expected_cn="server.local")
        if not is_valid:
            console.print(f"[red]Server certificate validation failed: {error}[/red]")
            return
        
        console.print("[green]Server certificate validated[/green]")
        server_cert_fp = get_certificate_fingerprint(server_cert)
        
        # Phase 2: Key Agreement for Authentication
        # Perform DH exchange for auth encryption
        p, g = generate_dh_params()
        client_auth_private = generate_private_key(p)
        client_auth_public = compute_public_value(g, client_auth_private, p)
        
        # Send client DH params
        dh_client = DHClientMessage(g=g, p=p, A=client_auth_public)
        send_message(sock, dh_client.model_dump())
        
        # Receive server DH response
        dh_server_data = receive_message(sock)
        if not dh_server_data or dh_server_data.get('type') != 'dh_server':
            console.print("[red]Invalid DH server message[/red]")
            return
        
        dh_server = DHServerMessage(**dh_server_data)
        server_auth_public = dh_server.B
        
        # Derive auth key
        auth_shared_secret = derive_shared_secret(server_auth_public, client_auth_private, p)
        auth_key = derive_session_key(auth_shared_secret)
        console.print("[cyan]Auth key established[/cyan]")
        
        # Phase 3: Authentication
        # Ask user for register or login
        auth_choice = console.input("[yellow]Register (r) or Login (l)? [/yellow]").strip().lower()
        
        if auth_choice == 'r':
            email = console.input("[cyan]Email: [/cyan]")
            username = console.input("[cyan]Username: [/cyan]")
            password = console.input("[cyan]Password: [/cyan]", password=True)
            
            # Create register message (plain password, server will hash)
            reg = RegisterMessage(
                email=email,
                username=username,
                pwd=password,  # Plain password
                salt=""  # Server generates salt
            )
            
            # Encrypt and send
            reg_json = json.dumps(reg.model_dump()).encode('utf-8')
            encrypted_reg = encrypt(auth_key, reg_json)
            send_message(sock, {"type": "register", "encrypted": encrypted_reg})
        else:
            email = console.input("[cyan]Email: [/cyan]")
            password = console.input("[cyan]Password: [/cyan]", password=True)
            
            # Create login message (plain password, server will hash with stored salt)
            login = LoginMessage(
                email=email,
                pwd=password,  # Plain password
                nonce=b64e(secrets.token_bytes(16))
            )
            
            # Encrypt and send
            login_json = json.dumps(login.model_dump()).encode('utf-8')
            encrypted_login = encrypt(auth_key, login_json)
            send_message(sock, {"type": "login", "encrypted": encrypted_login})
        
        # Receive auth response
        auth_response = receive_message(sock)
        if not auth_response or auth_response.get('type') != 'auth_success':
            error = auth_response.get('error', 'Unknown error') if auth_response else 'No response'
            console.print(f"[red]Authentication failed: {error}[/red]")
            return
        
        console.print(f"[green]{auth_response.get('message', 'Authentication successful')}[/green]")
        
        # Phase 4: Session Key Establishment
        # New DH exchange for chat session
        p, g = generate_dh_params()
        client_session_private = generate_private_key(p)
        client_session_public = compute_public_value(g, client_session_private, p)
        
        # Send client session DH
        session_dh_client = DHClientMessage(g=g, p=p, A=client_session_public)
        send_message(sock, session_dh_client.model_dump())
        
        # Receive server session DH
        session_dh_data = receive_message(sock)
        if not session_dh_data or session_dh_data.get('type') != 'dh_server':
            console.print("[red]Invalid session DH server message[/red]")
            return
        
        session_dh_server = DHServerMessage(**session_dh_data)
        server_session_public = session_dh_server.B
        
        # Derive session key
        session_shared_secret = derive_shared_secret(server_session_public, client_session_private, p)
        session_key = derive_session_key(session_shared_secret)
        console.print("[cyan]Session key established[/cyan]")
        
        # Phase 5: Data Plane - Encrypted Chat
        # Initialize transcript
        transcript_path = f"transcripts/client_{host}_{port}_{now_ms()}.txt"
        transcript = Transcript(transcript_path)
        seqno = 1
        
        console.print("[yellow]Entering chat mode. Type messages or 'quit' to end session.[/yellow]")
        
        # Start receiving thread
        def receive_messages():
            nonlocal seqno
            expected_seqno = 1
            while True:
                msg_data = receive_message(sock)
                if not msg_data:
                    break
                
                if msg_data.get('type') == 'error':
                    error = msg_data.get('error', 'Unknown error')
                    console.print(f"[red]Error: {error}[/red]")
                    if error == "REPLAY":
                        continue
                    elif error == "SIG_FAIL":
                        continue
                    else:
                        break
                
                if msg_data.get('type') == 'receipt':
                    receipt = SessionReceipt(**msg_data)
                    console.print(f"[cyan]Received server receipt[/cyan]")
                    
                    # Generate client receipt
                    transcript_hash = transcript.compute_hash()
                    receipt_data = f"{transcript_hash}".encode('utf-8')
                    receipt_sig = sign_with_cert_private_key(client_cert, client_key, receipt_data)
                    
                    client_receipt = SessionReceipt(
                        peer="client",
                        first_seq=transcript.get_first_seq() or 0,
                        last_seq=transcript.get_last_seq() or 0,
                        transcript_sha256=transcript_hash,
                        sig=receipt_sig
                    )
                    send_message(sock, client_receipt.model_dump())
                    console.print("[green]Session receipt sent[/green]")
                    break
                
                if msg_data.get('type') != 'msg':
                    continue
                
                msg = ChatMessage(**msg_data)
                
                # Replay protection
                if msg.seqno != expected_seqno:
                    console.print(f"[red]Replay detected: expected {expected_seqno}, got {msg.seqno}[/red]")
                    continue
                
                # Verify signature
                hash_input = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
                hash_bytes = hashlib.sha256(hash_input).digest()
                
                if not verify_with_cert(server_cert, hash_bytes, msg.sig):
                    console.print("[red]Signature verification failed[/red]")
                    continue
                
                # Decrypt message
                try:
                    plaintext_bytes = decrypt(session_key, msg.ct)
                    plaintext = plaintext_bytes.decode('utf-8')
                except Exception as e:
                    console.print(f"[red]Decryption failed: {e}[/red]")
                    continue
                
                # Add to transcript
                transcript.append(
                    msg.seqno,
                    msg.ts,
                    msg.ct,
                    msg.sig,
                    server_cert_fp
                )
                
                console.print(f"[blue][Server][/blue]: {plaintext}")
                expected_seqno += 1
        
        recv_thread = threading.Thread(target=receive_messages, daemon=True)
        recv_thread.start()
        
        # Send messages
        while True:
            try:
                plaintext = console.input()
                if not plaintext:
                    continue
                
                if plaintext.strip().lower() == 'quit':
                    # Send receipt and exit
                    transcript_hash = transcript.compute_hash()
                    receipt_data = f"{transcript_hash}".encode('utf-8')
                    receipt_sig = sign_with_cert_private_key(client_cert, client_key, receipt_data)
                    
                    client_receipt = SessionReceipt(
                        peer="client",
                        first_seq=transcript.get_first_seq() or 0,
                        last_seq=transcript.get_last_seq() or 0,
                        transcript_sha256=transcript_hash,
                        sig=receipt_sig
                    )
                    send_message(sock, client_receipt.model_dump())
                    break
                
                # Encrypt message
                plaintext_bytes = plaintext.encode('utf-8')
                ciphertext = encrypt(session_key, plaintext_bytes)
                
                # Compute signature
                timestamp = now_ms()
                hash_input = f"{seqno}{timestamp}{ciphertext}".encode('utf-8')
                hash_bytes = hashlib.sha256(hash_input).digest()
                signature = sign_with_cert_private_key(client_cert, client_key, hash_bytes)
                
                # Create and send message
                msg = ChatMessage(
                    seqno=seqno,
                    ts=timestamp,
                    ct=ciphertext,
                    sig=signature
                )
                send_message(sock, msg.model_dump())
                
                # Add to transcript
                transcript.append(
                    seqno,
                    timestamp,
                    ciphertext,
                    signature,
                    server_cert_fp
                )
                
                seqno += 1
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                break
        
        console.print("[yellow]Chat session ended[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()


if __name__ == "__main__":
    main()
