import os
import sys
import hashlib
import time
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CONFIGURATION
STEGO_IMAGE_PATH = "BLACK_BOX_MANIFEST.png"
OUTPUT_PROTO_PATH = "extracted_arc_audit.proto"
MAGIC_MARKER = b"<<PROTO_START>>"
SECURITY_STATE_FILE = ".security_state"

# Security Policy
MAX_ATTEMPTS = 3
COOLDOWN_SECONDS = 10 * 60 * 60 # 10 Hours

def derive_key(password: str, salt: bytes) -> bytes:
    key = hashlib.new('sha256', password.encode() + salt).digest()
    return key

def load_security_state():
    if not os.path.exists(SECURITY_STATE_FILE):
        return {"failures": 0, "lockout_timestamp": 0}
    try:
        with open(SECURITY_STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {"failures": 0, "lockout_timestamp": 0}

def save_security_state(state):
    with open(SECURITY_STATE_FILE, "w") as f:
        json.dump(state, f)

def check_security():
    state = load_security_state()
    current_time = time.time()
    
    # Check if locked out
    if state["lockout_timestamp"] > 0:
        elapsed = current_time - state["lockout_timestamp"]
        if elapsed < COOLDOWN_SECONDS:
            remaining = int((COOLDOWN_SECONDS - elapsed) / 60)
            return False, f"SECURITY LOCKDOWN ACTIVE. Protocol frozen for {remaining} minutes."
        else:
            # Cooldown over, reset
            state["failures"] = 0
            state["lockout_timestamp"] = 0
            save_security_state(state)

    return True, state

def record_failure(state):
    state["failures"] += 1
    print(f"[!] Authentication Failed. Attempt {state['failures']}/{MAX_ATTEMPTS}")
    
    if state["failures"] >= MAX_ATTEMPTS:
        state["lockout_timestamp"] = time.time()
        print(f"[!!!] MAXIMUM ATTEMPTS EXCEEDED. LOCKDOWN INITIATED (10 HOURS).")
    
    save_security_state(state)

def record_success(state):
    if state["failures"] > 0:
        state["failures"] = 0
        state["lockout_timestamp"] = 0
        save_security_state(state)

def extract(password_attempt):
    # 1. Security Check
    allowed, state_or_msg = check_security()
    if not allowed:
        print(f"[!] ACCESS DENIED: {state_or_msg}")
        return False

    state = state_or_msg # It's the state dict

    if not os.path.exists(STEGO_IMAGE_PATH):
        print(f"[!] Error: {STEGO_IMAGE_PATH} not found.")
        return False

    # 2. Extract Payload
    try:
        with open(STEGO_IMAGE_PATH, "rb") as f:
            data = f.read()
            
        marker_index = data.find(MAGIC_MARKER)
        if marker_index == -1:
            print("[!] Error: No logic contract found in this artifact.")
            return False
            
        payload = data[marker_index + len(MAGIC_MARKER):]
        
        # Parse: SALT (16) | NONCE (12) | CIPHERTEXT
        if len(payload) < 28:
            print("[!] Error: Payload corrupted.")
            return False
            
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        
        # 3. Decrypt
        key = derive_key(password_attempt, salt)
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # On success
        record_success(state)
        
        with open(OUTPUT_PROTO_PATH, "wb") as f:
            f.write(plaintext)
            
        print(f"[SUCCESS] Logic Contract extracted to: {OUTPUT_PROTO_PATH}")
        print(f"          Size: {len(plaintext)} bytes")
        # Print content for verification
        print("\n--- [LOGIC CONTRACT] ---")
        print(plaintext.decode())
        print("------------------------")
        return True

    except Exception as e:
        # Decryption failure usually throws an exception here (invalid tag)
        record_failure(state)
        # print(f"DEBUG: {e}") 
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python stega_extract.py <PASSWORD>")
    else:
        extract(sys.argv[1])
