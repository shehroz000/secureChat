"""MySQL users table + salted hashing (no chat storage)."""

import os
import sys
import secrets
import hashlib
import pymysql
from dotenv import load_dotenv
from typing import Optional, Tuple

load_dotenv()


def get_db_connection():
    """Get MySQL database connection."""
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'scuser'),
        password=os.getenv('DB_PASSWORD', 'scpass'),
        database=os.getenv('DB_NAME', 'securechat'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def init_database():
    """Initialize database tables."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    PRIMARY KEY (username),
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        conn.commit()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        conn.close()


def generate_salt() -> bytes:
    """Generate a random 16-byte salt."""
    return secrets.token_bytes(16)


def hash_password(password: str, salt: bytes) -> str:
    """
    Compute salted password hash.
    pwd_hash = hex(SHA256(salt || password))
    
    Args:
        password: Plaintext password
        salt: 16-byte salt
        
    Returns:
        Hex-encoded SHA-256 hash (64 characters)
    """
    combined = salt + password.encode('utf-8')
    hash_bytes = hashlib.sha256(combined).digest()
    return hash_bytes.hex()


def register_user(email: str, username: str, password: str) -> Tuple[bool, Optional[str]]:
    """
    Register a new user in the database.
    
    Args:
        email: User email
        username: Username (must be unique)
        password: Plaintext password
        
    Returns:
        Tuple of (success, error_message)
        If successful, returns (True, None)
        If failed, returns (False, error_message)
    """
    conn = get_db_connection()
    try:
        # Check if username or email already exists
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT username, email FROM users WHERE username = %s OR email = %s",
                (username, email)
            )
            existing = cursor.fetchone()
            if existing:
                if existing['username'] == username:
                    return (False, "Username already exists")
                else:
                    return (False, "Email already registered")
        
        # Generate salt and hash password
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        # Insert user
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
        conn.commit()
        return (True, None)
    except Exception as e:
        conn.rollback()
        return (False, str(e))
    finally:
        conn.close()


def verify_user(email: str, password: str) -> Tuple[bool, Optional[str]]:
    """
    Verify user credentials.
    
    Args:
        email: User email
        password: Plaintext password
        
    Returns:
        Tuple of (is_valid, username_or_error)
        If valid, returns (True, username)
        If invalid, returns (False, error_message)
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            
            if not user:
                return (False, "User not found")
            
            # Recompute hash with stored salt
            salt = user['salt']
            computed_hash = hash_password(password, salt)
            
            # Compare hashes
            if computed_hash == user['pwd_hash']:
                return (True, user['username'])
            else:
                return (False, "Invalid password")
    except Exception as e:
        return (False, str(e))
    finally:
        conn.close()


def get_user_salt(email: str) -> Optional[bytes]:
    """
    Get salt for a user (used during login for client-side hashing).
    
    Args:
        email: User email
        
    Returns:
        Salt bytes or None if user not found
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT salt FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            if user:
                return user['salt']
            return None
    except Exception as e:
        return None
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_database()
    else:
        print("Usage: python -m app.storage.db --init")
