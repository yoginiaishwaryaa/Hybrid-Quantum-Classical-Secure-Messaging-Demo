# 🔐 Hybrid Quantum-Classical Secure Messaging Demo

This project demonstrates an **educational hybrid cryptographic protocol** that combines **simulated Quantum Key Distribution (QKD)** with **classical cryptography** components — including **X25519 (ECDH KEM)**, **AES-256-GCM**, and **Ed25519** — to ensure **confidentiality**, **integrity**, and **authenticity** of messages.

The system is designed for **educational and research purposes**, simulating how post-quantum migration could look in hybrid cryptographic architectures.

---

##  Overview

### Hybrid Flow Summary

1. **Simulated QKD** – Produces a shared random key for both sender and receiver (simulating a photon-based QKD link).  
2. **X25519 Key Exchange (ECDH KEM)** – Derives a shared secret from an ephemeral keypair.  
3. **HKDF-SHA256** – Expands the shared secret into a 256-bit AES key.  
4. **AES-256-GCM Encryption** – Provides confidentiality and integrity of the plaintext.  
5. **Ed25519 Digital Signature** – Authenticates the sender and ensures message integrity.  
6. **Trust Models**
   - **PRE_SHARED**: Receiver has a static table of trusted sender keys.
   - **CA_SIGNED**: A simulated Certificate Authority signs sender keys.
7. **Replay & Freshness Protection** – Timestamps and nonces are validated to prevent message reuse.

---

##  Components Used

| Function | Implementation | Description |
|-----------|----------------|-------------|
| **QKD Simulation** | `simulate_qkd()` | Simulates a shared random key (no real quantum hardware). |
| **KEM** | `X25519` | Classical elliptic-curve Diffie-Hellman key exchange. |
| **Signature** | `Ed25519` | Digital signature for authenticity and integrity. |
| **Symmetric Encryption** | `AES-256-GCM` | Authenticated encryption for confidentiality. |
| **Key Derivation** | `HKDF-SHA256` | Derives cryptographic keys from shared secrets. |
| **Freshness & Replay** | Timestamp + Nonce | Prevents replay and stale message attacks. |

---

##  Conceptual Architecture

```text
Sender                            Receiver
  │                                   │
  │-- Simulated QKD shared key -------│
  │                                   │
  │-- X25519 Encapsulation ---------->│
  │                                   │
  │-- AES-GCM(plaintext) ------------>│
  │                                   │
  │-- Ed25519(Signature) ------------>│
  │                                   │
  │<-- Receiver verifies + decrypts --│
