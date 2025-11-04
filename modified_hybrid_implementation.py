"""
Replacement:
QKD	- Real QKD hardware not available, but simulated
(produce same random key for Sender & Receiver)
Kyber (PQC KEM)	- Replaced by X25519
(X25519 is a classical elliptic-curve Diffie-Hellman (ECDH) KEM)
(same key exchange concept of generating a secret key)
Dilithium (PQC Signature) - Replaced by Ed25519	
(Ed25519 is a modern pre-quantum digital signature scheme)
AES-256-GCM	- AES-GCM provides confidentiality + authenticity
(symmetric encryption)

Hybrid flow (educational demo) with:
 - QKD (simulated) -> used to derive recipient X25519 keypair
 - Sender encapsulates with recipient public key -> (encap_blob, shared_secret)
 - HKDF-SHA256(shared_secret) -> AES-256 key
 - AES-256-GCM encrypt plaintext
 - Ed25519 signature over (protocol_version || timestamp || encapsulation || nonce || ciphertext || aad)
 - Trust models supported:
      * PRE_SHARED: receiver has a mapping of sender_id -> sender_signing_pub
      (the receiver has a table of the senders and their signature key, whenever a message is received they lookup the table for verification)
      * CA_SIGNED: a CA signs sender's signing public key (1-level chain). Receiver trusts CA pub.
      (Receiver trusts CA → so it also trusts Sender's key because CA vouched for them)

 - Replay & freshness:
      * timestamp checked against a freshness window (configurable)
      * nonces recorded per (sender_id) to detect replays
 - Signature is verified before decapsulation.

NOTES:
 - X25519 private key from QKD material as QKD generates public/private key.
 - Ed25519 stands for signature; replace with Dilithium (pyoqs) in PQC migration.
 - QKD is used for generating a random key for the sender and receiver so that there is no eavesdropping using photons but here the key is simulated
"""

import os
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# -------------- Configuration --------------

QKD_BITS = 256
HKDF_INFO_KEYGEN = b"QKD->X25519-keygen"
HKDF_INFO_AES = b"KEM-shared->AES256"
AES_KEY_LEN = 32
AES_GCM_NONCE_LEN = 12
# Trust mode: "PRE_SHARED" or "CA_SIGNED"
TRUST_MODE = "CA_SIGNED" 
# Freshness window (seconds) - 5 minutes (included in signed data)
FRESHNESS_WINDOW = 300 
# Protocol version (included in signed data)
PROTOCOL_VERSION = b"HYBRID-V1"


# -------------- Replay store --------------

# to make sure that the receiver is able to identify if the same package sent by the invader
_seen_nonces: Dict[str, set] = {}

# checks for the reoccurrance of the package accordingly the value is returned
def record_nonce(sender_id: str, nonce: bytes) -> bool:
    s = _seen_nonces.setdefault(sender_id, set())
    if nonce in s:
        return False
    s.add(nonce)
    return True

# -------------- Helpers --------------

# takes the initial key material (ikm) and convert it to cryptographically strong key using SHA-256
def hkdf_sha256(ikm: bytes, info: bytes, length: int):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(ikm)

# used for encrypting the message - sender's side
def aes_encrypt(aes_key: bytes, plaintext: bytes, aad: bytes = None):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AES_GCM_NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

# used for decrypting the message - receiver's side
def aes_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

# used for getting the time at the point of sending the package
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# to verify the timing in the receiver's side, to make sure that it is within the freshness window
def parse_iso_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


# -------------- QKD simulation + key derivation --------------

# used for the common key generation
def simulate_qkd(length_bits=QKD_BITS) -> bytes:
    """Simulate a shared quantum key (same for both sides)."""
    key = os.urandom(length_bits // 8)
    return key  # 🔹 CHANGE: return one common key instead of (alice,bob)

# used for generating a key pair (public and private) using which a secret key is generated
def derive_x25519_keypair_from_qkd(qkd_key: bytes) -> Tuple[x25519.X25519PrivateKey, bytes]:
    sk_bytes = hkdf_sha256(qkd_key, HKDF_INFO_KEYGEN, length=32)
    priv = x25519.X25519PrivateKey.from_private_bytes(sk_bytes)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub_bytes


# -------------- Encapsulation / decapsulation --------------

# generating the secret key in the sender's side
def encapsulate_with_x25519(recipient_pub_bytes: bytes):
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_pub_bytes)
    shared_secret = eph_priv.exchange(recipient_pub)
    return eph_pub_bytes, shared_secret

# generating the secret key in the receiver's side
def decapsulate_with_x25519(eph_pub_bytes: bytes, recipient_priv: x25519.X25519PrivateKey):
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_secret = recipient_priv.exchange(eph_pub)
    return shared_secret


# -------------- Signature helpers --------------

# a common key generation for the package signature
def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub_bytes

# to sign the package
def sign_ed25519(priv: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return priv.sign(message)

# to verify the package
def verify_ed25519(pub_bytes: bytes, message: bytes, signature: bytes) -> None:
    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    pubkey.verify(signature, message)


# -------------- CA helpers --------------

# to issue the CA certificate so that the receiver trust the sender
def ca_issue_certificate(ca_priv, subject_pub_bytes: bytes, subject_id: str) -> bytes:
    cert = {"subject_id": subject_id, "subject_pub_hex": subject_pub_bytes.hex()}
    cert_bytes = json.dumps(cert, sort_keys=True).encode()
    signature = ca_priv.sign(cert_bytes)
    return cert_bytes + b"||" + signature

# to verify the sender
def ca_verify_certificate(ca_pub_bytes: bytes, certificate: bytes) -> Tuple[str, bytes]:
    cert_bytes, signature = certificate.split(b"||", 1)
    verify_ed25519(ca_pub_bytes, cert_bytes, signature)
    cert = json.loads(cert_bytes.decode())
    return cert["subject_id"], bytes.fromhex(cert["subject_pub_hex"])


# -------------- Sender prepares package --------------

def sender_prepare_package(
    plaintext: bytes,
    aad: Optional[bytes],
    recipient_pub_bytes: bytes,
    sender_sig_priv: ed25519.Ed25519PrivateKey,
    sender_id: str,
    attach_sender_cert: Optional[bytes] = None
):
    # secret key generation
    encapsulation_blob, shared_secret = encapsulate_with_x25519(recipient_pub_bytes)
    # aes standard key generation
    aes_key = hkdf_sha256(shared_secret, HKDF_INFO_AES, length=AES_KEY_LEN)
    # preparation of the package
    nonce, ciphertext = aes_encrypt(aes_key, plaintext, aad)
    timestamp = now_utc_iso().encode()

    # signing the package
    to_sign = PROTOCOL_VERSION + b"|" + timestamp + b"|" + encapsulation_blob + nonce + ciphertext + (aad if aad else b"")
    signature = sign_ed25519(sender_sig_priv, to_sign)

    package = {
        "sender_id": sender_id,
        "protocol_version": PROTOCOL_VERSION.decode(),
        "timestamp": timestamp.decode(),
        "encapsulation_blob": encapsulation_blob.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "aad": aad.decode() if aad else None,
        "signature": signature.hex(),
    }

    # according to the method, the package is forwarded
    if attach_sender_cert:
        package["sender_cert"] = attach_sender_cert.hex()
    else:
        package["sender_pub"] = sender_sig_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
    return package, shared_secret

# -------------- Receiver processes package --------------

def receiver_process_package(
    package: dict,
    recipient_priv: x25519.X25519PrivateKey,
    trusted_pub_map: Dict[str, bytes] = None,
    ca_pub_bytes: Optional[bytes] = None
):
    # Extract fields from the received package
    sender_id = package.get("sender_id")                        # unique ID of the sender
    proto = package.get("protocol_version")                    # protocol version string
    timestamp_str = package.get("timestamp")                   # ISO timestamp of message creation
    encap_blob = bytes.fromhex(package["encapsulation_blob"])  # ephemeral public key from sender
    nonce = bytes.fromhex(package["nonce"])                    # AES-GCM nonce used during encryption
    ciphertext = bytes.fromhex(package["ciphertext"])          # encrypted payload
    aad = package["aad"].encode() if package.get("aad") else None  # additional authenticated data (optional)
    signature = bytes.fromhex(package["signature"])            # sender's Ed25519 signature over message

    # Verify protocol version
    if proto.encode() != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version")

    # Verify freshness of timestamp
    # convert ISO string to datetime object
    ts = parse_iso_timestamp(timestamp_str)  
    now = datetime.now(timezone.utc)
    if abs((now - ts).total_seconds()) > FRESHNESS_WINDOW:
        # message too old or outside allowed window
        raise ValueError("Stale timestamp")  

    # Retrieve sender's signing public key
    if TRUST_MODE == "PRE_SHARED":
        # sender public key is pre-shared in a mapping
        if trusted_pub_map is None or sender_id not in trusted_pub_map:
            raise ValueError("Unknown sender")
        sender_pub_bytes = trusted_pub_map[sender_id]
    elif TRUST_MODE == "CA_SIGNED":
        # sender public key is in a certificate issued by CA
        cert_bytes = bytes.fromhex(package["sender_cert"])
        if ca_pub_bytes is None:
            raise ValueError("Missing CA public key")
        subject_id, subject_pub = ca_verify_certificate(ca_pub_bytes, cert_bytes)
        if subject_id != sender_id:
            raise ValueError("Certificate subject mismatch")
        sender_pub_bytes = subject_pub
    else:
        raise ValueError("Unsupported trust model")

    # Verify sender's signature
    to_verify = PROTOCOL_VERSION + b"|" + timestamp_str.encode() + b"|" + encap_blob + nonce + ciphertext + (aad if aad else b"")
    verify_ed25519(sender_pub_bytes, to_verify, signature)  # raises InvalidSignature if invalid

    # Replay protection: reject if nonce already seen
    if not record_nonce(sender_id, nonce):
        raise ValueError("Replay detected")  

    # Decapsulate shared secret
    shared_secret = decapsulate_with_x25519(encap_blob, recipient_priv)
    # Derive AES key from shared secret using HKDF-SHA256
    aes_key = hkdf_sha256(shared_secret, HKDF_INFO_AES, length=AES_KEY_LEN)
    # Decrypt ciphertext with AES-GCM using derived key and nonce
    plaintext = aes_decrypt(aes_key, nonce, ciphertext, aad)
    
    # Return decrypted message
    return plaintext

# -------------- Demo --------------
if __name__ == "__main__":
    # Simulate QKD and generate a common X25519 keypair
    qkd_shared = simulate_qkd()
    common_priv, common_pub_bytes = derive_x25519_keypair_from_qkd(qkd_shared)

    # Sender signing keys
    sender_priv, sender_pub_bytes = generate_ed25519_keypair()
    sender_id = "sender-device-1"

    # Pre-shared trust map if using PRE_SHARED mode
    trusted_map = {sender_id: sender_pub_bytes} if TRUST_MODE == "PRE_SHARED" else None

    # Setup CA if using CA_SIGNED mode
    ca_pub_bytes = None
    sender_cert = None
    if TRUST_MODE == "CA_SIGNED":
        ca_priv, ca_pub_bytes = generate_ed25519_keypair()
        sender_cert = ca_issue_certificate(ca_priv, sender_pub_bytes, sender_id)

    # --- User input and fallback ---
    plaintext_input = input("Enter the plaintext message: ").encode()
    if not plaintext_input:
        print("No message entered. Using default confidential message for testing...\n")
        plaintext_input = b"Default: Confidential message for hybrid cryptosystem."

    aad_input = f"device:{sender_id};ts:{now_utc_iso()}".encode()

    # Sender builds the package
    package, sender_shared_secret = sender_prepare_package(
        plaintext_input, aad_input, common_pub_bytes, sender_priv, sender_id,
        attach_sender_cert=sender_cert if TRUST_MODE == "CA_SIGNED" else None
    )

    # Simulate sending/receiving (JSON round-trip)
    serialized = json.dumps(package)
    received_pkg = json.loads(serialized)

    print("\nReceiver processing package in TRUST_MODE =", TRUST_MODE)
    recovered = receiver_process_package(
        received_pkg, common_priv,
        trusted_pub_map=trusted_map, ca_pub_bytes=ca_pub_bytes
    )
    print("Receiver recovered plaintext:", recovered.decode())
    assert recovered == plaintext_input
    print("\nDemo success: Message verified and decrypted correctly.\n")


    # --- Edge Case Simulation (always runs) ---
    print("---- Simulating Edge Cases ----")

    # Replay attack - reuses the same package twice.
    try:
        receiver_process_package(received_pkg, common_priv, trusted_pub_map=trusted_map, ca_pub_bytes=ca_pub_bytes)
    except Exception as e:
        print("\nReplay attack detected:", e)

    # Ciphertext tampering - changes one byte in ciphertext.
    tampered_pkg = dict(received_pkg)
    tampered_cipher = bytearray(bytes.fromhex(tampered_pkg["ciphertext"]))
    if tampered_cipher:
        tampered_cipher[0] ^= 0x01  # flip one bit
    tampered_pkg["ciphertext"] = tampered_cipher.hex()
    try:
        receiver_process_package(tampered_pkg, common_priv, trusted_pub_map=trusted_map, ca_pub_bytes=ca_pub_bytes)
    except Exception as e:
        print("\nCiphertext tampering detected:", e)

    # Stale timestamp - pretends message came from the past.
    from datetime import timedelta
    stale_pkg = dict(received_pkg)
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=FRESHNESS_WINDOW + 60)).isoformat()
    stale_pkg["timestamp"] = old_time
    try:
        receiver_process_package(stale_pkg, common_priv, trusted_pub_map=trusted_map, ca_pub_bytes=ca_pub_bytes)
    except Exception as e:
        print("\nStale timestamp detected:", e)
