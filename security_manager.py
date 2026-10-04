import os
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureTelemetryStore:
    def __init__(self, key_file="telemetry.key"):
        self.key_file = key_file
        # Generate or load traditional high-entropy operational system secrets
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                self.secret_key = f.read()
        else:
            self.secret_key = AESGCM.generate_key(bit_length=256)
            with open(key_file, "wb") as f:
                f.write(self.secret_key)
        
        self.aesgcm = AESGCM(self.secret_key)
        self.last_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    def compute_tamper_evident_chain(self, dataframe):
        """Generates a sequential cryptographic hash-chain across rows to prevent trace modification."""
        hash_chain = []
        current_prev = self.last_hash
        
        for idx, row in dataframe.iterrows():
            row_data = row.to_json()
            # Combine current block parameters with the previous block hash link
            combined_block = f"{row_data}{current_prev}".encode('utf-8')
            current_hash = hashlib.sha256(combined_block).hexdigest()
            hash_chain.append(current_hash)
            current_prev = current_hash
            
        dataframe['Telemetry_Hash_Link'] = hash_chain
        return dataframe

    def encrypt_telemetry_payload(self, file_path):
        """Encrypts data logs using modern AES-256-GCM primitives (Quantum-safe hybrid simulation placeholder)."""
        if not os.path.exists(file_path):
            return
            
        with open(file_path, "rb") as f:
            data = f.read()
            
        nonce = os.urandom(12)
        encrypted_data = self.aesgcm.encrypt(nonce, data, None)
        
        with open(f"{file_path}.enc", "wb") as f:
            f.write(nonce + encrypted_data)