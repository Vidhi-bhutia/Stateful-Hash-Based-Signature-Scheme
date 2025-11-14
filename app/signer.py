"""
signer.py

Signs document hashes using either:
 - PQC library (if present, e.g. pyxmss/pylms/pyspx)
 - Fallback Ed25519 (NOT PQC) for demo.

Exports:
 - sign_file(filepath, priv_key_path, algo) -> signature bytes
 - hash_file(filepath) -> hex digest
"""

import hashlib
from pathlib import Path

def hash_file(filepath, block_size=65536, hash_name="sha256"):
    h = hashlib.new(hash_name)
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            h.update(block)
    return h.hexdigest()

def sign_with_fallback_ed25519(message_bytes, priv_key_path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with open(priv_key_path, "rb") as f:
        priv_pem = f.read()
    sk = load_pem_private_key(priv_pem, password=None)
    sig = sk.sign(message_bytes)
    return sig

def sign_file(filepath, priv_key_path, algo_hint=None):
    """
    Return signature bytes and algorithm name used.
    If a PQC lib is available it will be used automatically.
    """
    p = Path(filepath)
    if not p.exists():
        raise FileNotFoundError(filepath)

    digest_hex = hash_file(filepath)
    message = digest_hex.encode("utf-8")  # sign the hex digest
    # Try XMSS
    try:
        import pyxmss
        # Hypothetical API - adjust to installed library
        sk = pyxmss.load_private_key(priv_key_path)
        sig = sk.sign(message)
        return sig, "xmss"
    except Exception:
        pass
    # Try LMS
    try:
        import pylms
        sk = pylms.load_private_key(priv_key_path)
        sig = sk.sign(message)
        return sig, "lms"
    except Exception:
        pass
    # Try SPHINCS
    try:
        import pyspx
        with open(priv_key_path,"rb") as f:
            sk = f.read()
        sig = pyspx.sign(message, sk)
        return sig, "sphincs"
    except Exception:
        pass

    # Fallback Ed25519
    sig = sign_with_fallback_ed25519(message, priv_key_path)
    return sig, "ed25519-fallback"
