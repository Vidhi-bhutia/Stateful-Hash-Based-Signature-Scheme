"""
verifier.py

Verifies signatures produced by signer.py. Supports the PQC libs if present,
otherwise supports Ed25519 fallback verification.

Exports:
 - verify_file(filepath, signature_bytes, pub_key_path) -> (bool, algo)
"""

from pathlib import Path
from signer import hash_file

def verify_with_fallback_ed25519(message_bytes, signature, pub_key_path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    with open(pub_key_path, "rb") as f:
        pub_pem = f.read()
    pk = load_pem_public_key(pub_pem)
    try:
        pk.verify(signature, message_bytes)
        return True
    except InvalidSignature:
        return False

def verify_file(filepath, signature, pub_key_path):
    p = Path(filepath)
    if not p.exists():
        raise FileNotFoundError(filepath)
    digest_hex = hash_file(filepath)
    message = digest_hex.encode("utf-8")

    # Try XMSS
    try:
        import pyxmss
        pk = pyxmss.load_public_key(pub_key_path)
        ok = pk.verify(message, signature)
        return ok, "xmss"
    except Exception:
        pass

    # Try LMS
    try:
        import pylms
        pk = pylms.load_public_key(pub_key_path)
        ok = pk.verify(message, signature)
        return ok, "lms"
    except Exception:
        pass

    # Try SPHINCS
    try:
        import pyspx
        with open(pub_key_path, "rb") as f:
            pk = f.read()
        ok = pyspx.verify(message, signature, pk)
        return ok, "sphincs"
    except Exception:
        pass

    # Fallback Ed25519
    ok = verify_with_fallback_ed25519(message, signature, pub_key_path)
    return ok, "ed25519-fallback"
