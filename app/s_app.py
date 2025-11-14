"""
Streamlit app for the PQ Notary prototype.
Start with: streamlit run app/s_app.py
"""

import streamlit as st
from pathlib import Path
import base64
import time

from signer import sign_file, hash_file
from verifier import verify_file
import storage
from keygen import generate_keypair, KEY_DIR

# Initialize DB
storage.init_db()

st.set_page_config(page_title="PQ Notary - Prototype", layout="centered")

st.title("PQ Notary — Post-Quantum (prototype) Document Notary")
st.markdown("""
**Goal:** upload documents, sign them (XMSS/LMS if available, otherwise Ed25519 fallback for demo),
store signature + metadata, and verify later.

**Important:** If you see `ed25519-fallback` it means PQC libraries were not found on your machine.
""")

menu = st.sidebar.selectbox("Menu", ["Generate Keys", "Sign Document", "Verify Document", "Records"])

# Generate Keys
if menu == "Generate Keys":
    st.header("Generate Keypair")
    st.write("Generates a keypair. Will prefer XMSS/LMS/SPHINCS libraries if installed.")
    name = st.text_input("Key name (prefix)", value="notary")
    if st.button("Generate Keypair"):
        info = generate_keypair()
        st.success(f"Generated keypair using algorithm: {info['algo']}")
        st.write("Key files saved to:", info['pub'], info['priv'])
        st.write("Meta file:", info['meta'])
        st.write("Key directory:", str(KEY_DIR))

# Sign Document
if menu == "Sign Document":
    st.header("Sign a Document")
    uploaded = st.file_uploader("Upload document to sign (pdf/docx/txt)", type=["pdf","docx","txt"])
    priv_key_file = st.file_uploader("Upload private key file (PEM or library-specific)", type=None)
    signer_name = st.text_input("Signer name / organization", value="Default Signer")
    if st.button("Sign"):
        if not uploaded:
            st.error("Please upload a document.")
        elif not priv_key_file:
            st.error("Please upload the private key file.")
        else:
            # Save uploaded files to disk (app keys directory)
            tmp_dir = Path.cwd() / "tmp_uploads"
            tmp_dir.mkdir(exist_ok=True)
            file_path = tmp_dir / uploaded.name
            with open(file_path, "wb") as f:
                f.write(uploaded.getvalue())
            pk_path = tmp_dir / priv_key_file.name
            with open(pk_path, "wb") as f:
                f.write(priv_key_file.getvalue())

            filehash = hash_file(file_path)
            sig_bytes, algo_used = sign_file(file_path, str(pk_path))
            # store signature and metadata in DB
            rowid = storage.add_signed_doc(uploaded.name, str(file_path), filehash, sig_bytes, signer_name, str(pk_path), algo_used)
            st.success(f"Signed and saved as record id {rowid} using {algo_used}")
            st.code(f"File hash (sha256): {filehash}")
            st.download_button("Download signature (binary)", data=sig_bytes, file_name=f"{uploaded.name}.sig")
            st.write("You can now verify this document using the same public key (or the stored record).")

# Verify Document
if menu == "Verify Document":
    st.header("Verify a Document")
    uploaded = st.file_uploader("Upload the document to verify", type=["pdf","docx","txt"])
    signature_file = st.file_uploader("Upload signature file (.sig or binary)", type=None)
    pub_key_file = st.file_uploader("Upload public key / verification key", type=None)
    if st.button("Verify"):
        if not (uploaded and signature_file and pub_key_file):
            st.error("Please provide document, signature, and public key.")
        else:
            tmp_dir = Path.cwd() / "tmp_uploads"
            tmp_dir.mkdir(exist_ok=True)
            file_path = tmp_dir / uploaded.name
            with open(file_path, "wb") as f:
                f.write(uploaded.getvalue())
            sig_bytes = signature_file.getvalue()
            pub_path = tmp_dir / pub_key_file.name
            with open(pub_path, "wb") as f:
                f.write(pub_key_file.getvalue())
            ok, algo = verify_file(file_path, sig_bytes, str(pub_path))
            if ok:
                st.success(f"Signature VALID (verified with algorithm: {algo})")
            else:
                st.error(f"Signature INVALID (checked algorithm: {algo})")
            st.code(f"Document hash (sha256): {hash_file(file_path)}")

# Records
if menu == "Records":
    st.header("Signed Document Records")
    rows = storage.get_all_signed_docs()
    if not rows:
        st.info("No signed documents yet.")
    else:
        for r in rows:
            with st.expander(f"Record {r['id']} — {r['filename']} (algo: {r['algo']})"):
                st.write("Signed by:", r["signer"])
                st.write("Timestamp (UTC):", r["timestamp"])
                st.write("File hash:", r["filehash"])
                st.write("Signature size (bytes):", len(r["signature"]) if r["signature"] else 0)
                st.write("Public key path stored (on server):", r["pubkey_path"])
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"Download signature {r['id']}", key=f"dl_{r['id']}"):
                        sig = r["signature"]
                        st.download_button("Download Signature", data=sig, file_name=f"{r['filename']}.sig")
                with col2:
                    if st.button(f"Verify using stored pubkey {r['id']}", key=f"v_{r['id']}"):
                        # try verifying with stored paths (note: paths are server-local)
                        # read pubkey
                        pub_path = r["pubkey_path"]
                        sig = r["signature"]
                        try:
                            ok, algo = verify_file(r["filepath"], sig, pub_path)
                            if ok:
                                st.success(f"Record {r['id']} verification: VALID ({algo})")
                            else:
                                st.error(f"Record {r['id']} verification: INVALID ({algo})")
                        except Exception as e:
                            st.error(f"Verification failed: {e}")
