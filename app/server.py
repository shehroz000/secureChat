"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import os
import sys
import json
import socket
import secrets
import hashlib
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
from app.crypto.pki import load_certificate, load_private_key, validate_certificate, get_certificate_fingerprint, get_certificate_cn, load_certificate_from_pem
from app.crypto.sign import sign_with_cert_private_key, verify_with_cert
from app.storage.db import register_user, verify_user, get_db_connection
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


def handle_client(conn: socket.socket, addr):
    """Handle a single client connection."""
    console.print(f"[green]New connection from {addr}[/green]")
    
    try:
        # Load server certificate and key
        server_cert_path = os.getenv('SERVER_CERT_PATH', 'certs/server.crt')
        server_key_path = os.getenv('SERVER_KEY_PATH', 'certs/server.key')
        ca_cert_path = os.getenv('CA_CERT_PATH', 'certs/ca.crt')
        
        server_cert = load_certificate(server_cert_path)
        server_key = load_private_key(server_key_path)
        ca_cert = load_certificate(ca_cert_path)
        
        # Phase 1: Control Plane - Certificate Exchange
        # Send server hello
        server_nonce = secrets.token_bytes(16)
        server_hello = ServerHelloMessage(
            server_cert=server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            nonce=b64e(server_nonce)
        )
        send_message(conn, server_hello.model_dump())
        console.print("[cyan]Sent server hello[/cyan]")
        
        # Receive client hello
        hello_data = receive_message(conn)
        if not hello_data or hello_data.get('type') != 'hello':
            console.print("[red]Invalid hello message[/red]")
            send_message(conn, ErrorMessage(error="BAD_CERT").model_dump())
            return
        
        hello = HelloMessage(**hello_data)
        client_cert = load_certificate_from_pem(hello.client_cert)
        
        # Validate client certificate
        is_valid, error = validate_certificate(client_cert, ca_cert)
        if not is_valid:
            console.print(f"[red]Certificate validation failed: {error}[/red]")
            send_message(conn, ErrorMessage(error="BAD_CERT").model_dump())
            return
        
        console.print("[green]Client certificate validated[/green]")
        client_cert_fp = get_certificate_fingerprint(client_cert)
        
        # Phase 2: Key Agreement for Authentication
        # Perform DH exchange for auth encryption
        p, g = generate_dh_params()
        server_auth_private = generate_private_key(p)
        server_auth_public = compute_public_value(g, server_auth_private, p)
        
        # Receive client DH params
        dh_client_data = receive_message(conn)
        if not dh_client_data or dh_client_data.get('type') != 'dh_client':
            console.print("[red]Invalid DH client message[/red]")
            send_message(conn, ErrorMessage(error="DH_FAIL").model_dump())
            return
        
        dh_client = DHClientMessage(**dh_client_data)
        client_auth_public = dh_client.A
        
        # Send server DH response
        dh_server = DHServerMessage(B=server_auth_public)
        send_message(conn, dh_server.model_dump())
        
        # Derive auth key
        auth_shared_secret = derive_shared_secret(client_auth_public, server_auth_private, p)
        auth_key = derive_session_key(auth_shared_secret)
        console.print("[cyan]Auth key established[/cyan]")
        
        # Phase 3: Authentication
        # Receive encrypted register/login
        auth_data = receive_message(conn)
        if not auth_data:
            return
        
        auth_type = auth_data.get('type')
        if auth_type not in ['register', 'login']:
            console.print("[red]Invalid auth message type[/red]")
            send_message(conn, ErrorMessage(error="AUTH_FAIL").model_dump())
            return
        
        # Decrypt auth message
        try:
            encrypted_data = auth_data.get('encrypted', '')
            if not encrypted_data:
                encrypted_data = auth_data.get('data', '')  # Fallback
            decrypted_bytes = decrypt(auth_key, encrypted_data)
            auth_payload = json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            console.print(f"[red]Decryption failed: {e}[/red]")
            send_message(conn, ErrorMessage(error="DECRYPT_FAIL").model_dump())
            return
        
        # Handle registration or login
        # Note: Client sends plain password, server handles salt generation and hashing
        username = None
        if auth_type == 'register':
            reg = RegisterMessage(**auth_payload)
            # Server generates salt and hashes password
            success, error = register_user(reg.email, reg.username, reg.pwd)
            if success:
                send_message(conn, {"type": "auth_success", "message": "Registration successful"})
                username = reg.username
            else:
                send_message(conn, ErrorMessage(error=f"REGISTER_FAIL: {error}").model_dump())
                return
        else:  # login
            login = LoginMessage(**auth_payload)
            # Server verifies password (hashes with stored salt)
            is_valid, result = verify_user(login.email, login.pwd)
            if is_valid:
                send_message(conn, {"type": "auth_success", "message": "Login successful"})
                username = result
            else:
                send_message(conn, ErrorMessage(error=f"LOGIN_FAIL: {result}").model_dump())
                return
        
        console.print(f"[green]User authenticated: {username}[/green]")
        
        # Phase 4: Session Key Establishment
        # New DH exchange for chat session
        p, g = generate_dh_params()
        server_session_private = generate_private_key(p)
        server_session_public = compute_public_value(g, server_session_private, p)
        
        # Receive client session DH
        session_dh_data = receive_message(conn)
        if not session_dh_data or session_dh_data.get('type') != 'dh_client':
            console.print("[red]Invalid session DH message[/red]")
            send_message(conn, ErrorMessage(error="DH_FAIL").model_dump())
            return
        
        session_dh_client = DHClientMessage(**session_dh_data)
        client_session_public = session_dh_client.A
        
        # Send server session DH
        session_dh_server = DHServerMessage(B=server_session_public)
        send_message(conn, session_dh_server.model_dump())
        
        # Derive session key
        session_shared_secret = derive_shared_secret(client_session_public, server_session_private, p)
        session_key = derive_session_key(session_shared_secret)
        console.print("[cyan]Session key established[/cyan]")
        
        # Phase 5: Data Plane - Encrypted Chat
        # Initialize transcript
        transcript_path = f"transcripts/server_{addr[0]}_{addr[1]}_{now_ms()}.txt"
        transcript = Transcript(transcript_path)
        expected_seqno = 1
        
        console.print("[yellow]Entering chat mode. Type messages or 'quit' to end session.[/yellow]")
        
        while True:
            # Receive message
            msg_data = receive_message(conn)
            if not msg_data:
                break
            
            if msg_data.get('type') == 'receipt':
                # Client sent receipt, generate our receipt
                receipt = SessionReceipt(**msg_data)
                console.print(f"[cyan]Received client receipt[/cyan]")
                
                # Generate server receipt
                transcript_hash = transcript.compute_hash()
                receipt_data = f"{transcript_hash}".encode('utf-8')
                receipt_sig = sign_with_cert_private_key(server_cert, server_key, receipt_data)
                
                server_receipt = SessionReceipt(
                    peer="server",
                    first_seq=transcript.get_first_seq() or 0,
                    last_seq=transcript.get_last_seq() or 0,
                    transcript_sha256=transcript_hash,
                    sig=receipt_sig
                )
                send_message(conn, server_receipt.model_dump())
                console.print("[green]Session receipt sent[/green]")
                break
            
            if msg_data.get('type') != 'msg':
                continue
            
            msg = ChatMessage(**msg_data)
            
            # Replay protection
            if msg.seqno != expected_seqno:
                console.print(f"[red]Replay detected: expected {expected_seqno}, got {msg.seqno}[/red]")
                send_message(conn, ErrorMessage(error="REPLAY").model_dump())
                continue
            
            # Verify signature
            hash_input = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
            hash_bytes = hashlib.sha256(hash_input).digest()
            
            if not verify_with_cert(client_cert, hash_bytes, msg.sig):
                console.print("[red]Signature verification failed[/red]")
                send_message(conn, ErrorMessage(error="SIG_FAIL").model_dump())
                continue
            
            # Decrypt message
            try:
                plaintext_bytes = decrypt(session_key, msg.ct)
                plaintext = plaintext_bytes.decode('utf-8')
            except Exception as e:
                console.print(f"[red]Decryption failed: {e}[/red]")
                send_message(conn, ErrorMessage(error="DECRYPT_FAIL").model_dump())
                continue
            
            # Add to transcript
            transcript.append(
                msg.seqno,
                msg.ts,
                msg.ct,
                msg.sig,
                client_cert_fp
            )
            
            console.print(f"[blue][{username}][/blue]: {plaintext}")
            expected_seqno += 1
            
            # Check for quit - wait for receipt instead of breaking immediately
            if plaintext.strip().lower() == 'quit':
                # Wait for client receipt
                receipt_data = receive_message(conn)
                if receipt_data and receipt_data.get('type') == 'receipt':
                    receipt = SessionReceipt(**receipt_data)
                    console.print(f"[cyan]Received client receipt[/cyan]")
                    
                    # Generate server receipt
                    transcript_hash = transcript.compute_hash()
                    receipt_data_bytes = f"{transcript_hash}".encode('utf-8')
                    receipt_sig = sign_with_cert_private_key(server_cert, server_key, receipt_data_bytes)
                    
                    server_receipt = SessionReceipt(
                        peer="server",
                        first_seq=transcript.get_first_seq() or 0,
                        last_seq=transcript.get_last_seq() or 0,
                        transcript_sha256=transcript_hash,
                        sig=receipt_sig
                    )
                    send_message(conn, server_receipt.model_dump())
                    console.print("[green]Session receipt sent[/green]")
                break
        
        console.print("[yellow]Chat session ended[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error handling client: {e}[/red]")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
        console.print(f"[dim]Connection closed[/dim]")


def main():
    """Main server function."""
    host = os.getenv('SERVER_HOST', 'localhost')
    port = int(os.getenv('SERVER_PORT', 8888))
    
    # Check if certificates exist
    if not os.path.exists('certs/server.crt') or not os.path.exists('certs/server.key'):
        console.print("[red]Server certificate or key not found. Please generate certificates first.[/red]")
        return
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        console.print(Panel(f"[green]Secure Chat Server listening on {host}:{port}[/green]", title="Server"))
        
        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Server shutting down...[/yellow]")
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
