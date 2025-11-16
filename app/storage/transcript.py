"""Append-only transcript + TranscriptHash helpers."""

import os
import hashlib
from typing import List, Optional
from app.common.utils import sha256_hex


class Transcript:
    """Append-only transcript for session messages."""
    
    def __init__(self, transcript_path: str):
        """
        Initialize transcript.
        
        Args:
            transcript_path: Path to transcript file
        """
        self.transcript_path = transcript_path
        self.entries: List[dict] = []
        self._load_existing()
    
    def _load_existing(self):
        """Load existing transcript entries from file."""
        if os.path.exists(self.transcript_path):
            with open(self.transcript_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split('|')
                    if len(parts) >= 5:
                        self.entries.append({
                            'seqno': int(parts[0]),
                            'ts': int(parts[1]),
                            'ct': parts[2],
                            'sig': parts[3],
                            'peer_cert_fp': parts[4]
                        })
    
    def append(
        self,
        seqno: int,
        timestamp: int,
        ciphertext: str,
        signature: str,
        peer_cert_fingerprint: str
    ):
        """
        Append a message entry to the transcript.
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded signature
            peer_cert_fingerprint: Peer certificate fingerprint (hex)
        """
        entry = {
            'seqno': seqno,
            'ts': timestamp,
            'ct': ciphertext,
            'sig': signature,
            'peer_cert_fp': peer_cert_fingerprint
        }
        self.entries.append(entry)
        
        # Append to file
        with open(self.transcript_path, 'a') as f:
            line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"
            f.write(line)
    
    def compute_hash(self) -> str:
        """
        Compute transcript hash.
        TranscriptHash = SHA256(concatenation of all log lines)
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        # Reconstruct all lines
        lines = []
        for entry in self.entries:
            line = f"{entry['seqno']}|{entry['ts']}|{entry['ct']}|{entry['sig']}|{entry['peer_cert_fp']}"
            lines.append(line)
        
        # Concatenate all lines
        transcript_data = '\n'.join(lines)
        
        # Compute SHA-256 hash
        return sha256_hex(transcript_data.encode('utf-8'))
    
    def get_first_seq(self) -> Optional[int]:
        """Get first sequence number."""
        if self.entries:
            return self.entries[0]['seqno']
        return None
    
    def get_last_seq(self) -> Optional[int]:
        """Get last sequence number."""
        if self.entries:
            return self.entries[-1]['seqno']
        return None
    
    def get_entry_count(self) -> int:
        """Get number of entries in transcript."""
        return len(self.entries)
