"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    type: str = "hello"
    client_cert: str  # PEM encoded certificate
    nonce: str  # base64 encoded nonce


class ServerHelloMessage(BaseModel):
    type: str = "server_hello"
    server_cert: str  # PEM encoded certificate
    nonce: str  # base64 encoded nonce


class RegisterMessage(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64 encoded salt


class LoginMessage(BaseModel):
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str  # base64 encoded nonce


class DHClientMessage(BaseModel):
    type: str = "dh_client"
    g: int  # generator
    p: int  # prime modulus
    A: int  # g^a mod p


class DHServerMessage(BaseModel):
    type: str = "dh_server"
    B: int  # g^b mod p


class ChatMessage(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int  # unix timestamp in milliseconds
    ct: str  # base64 encoded ciphertext
    sig: str  # base64 encoded RSA signature


class SessionReceipt(BaseModel):
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex string
    sig: str  # base64 encoded RSA signature


class ErrorMessage(BaseModel):
    type: str = "error"
    error: str  # Error code: BAD_CERT, SIG_FAIL, REPLAY, etc.
