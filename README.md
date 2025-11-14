# Stateful Hash-Based Signature Scheme 
**Project / Paper:** _Stateful Hash-Based Signature Scheme for Long-Term Document Storage_  
**Authors:** Vidhi Bhutia, Shayaree Lodh

## Overview

This repository contains a prototype implementing a notary-style, stateful hash-based signature scheme for long-term document storage. The implementation is designed as a research prototype and demonstration for the paper. It provides:

- Key generation (attempts to use XMSS/LMS/SPHINCS where available; falls back to Ed25519 for demo).
- File hashing and signing.
- Signature verification.
- A tiny SQLite-based storage for signed-file metadata.
- A Streamlit web UI (`app/s_app.py`) to interact with the system.

**Important:** The code contains fallbacks (Ed25519) for environments where post-quantum libraries are not installed. Ed25519 is **not** quantum-safe — for production/post-quantum claims you must install and use a vetted XMSS/LMS/SPHINCS implementation.

## Repository layout

```
crypto_code/
  ├─ app/
  │   ├─ keygen.py        # key generation, wrapper for various PQC libs and fallback
  │   ├─ signer.py        # hash & sign functions
  │   ├─ verifier.py      # verify functions with PQC and fallback checks
  │   ├─ storage.py       # simple SQLite storage & helper functions
  │   └─ s_app.py         # Streamlit UI (entry point: streamlit run app/s_app.py)
  ├─ data/
  │   ├─ files.db         # placeholder DB used by storage module
  │   └─ signed_files.db  # placeholder signed files DB (may be created at runtime)
  ├─ keys/                # default directory for generated keys
  └─ requirements.txt     # recommended Python packages
```

## Prerequisites

- Python 3.10 or 3.11 recommended.
- git (optional)
- A Unix-like shell (Linux/macOS) or Windows PowerShell / WSL.
- Optional (for true post-quantum signing): one or more of the following Python packages that expose XMSS/LMS/SPHINCS functionality:
  - `pyhsslms`, `pylms`, `pyspx`, or other maintained libraries implementing XMSS/LMS/SPHINCS.
  - The code will attempt to import supported libraries at runtime and fall back to Ed25519 if none are found.

## Setup — step by step

1. **Unpack the repository**
   Extract the provided ZIP and change into its root directory (where `app/` lives).  
   Example:
   ```bash
   cd crypto_code/app
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate      # Linux / macOS
   venv\Scripts\activate         # Windows PowerShell
   ```

3. **Install dependencies**
   ```bash
   pip install --upgrade pip
   pip install -r ../requirements.txt
   ```  

4. **Run Streamlit App**
   ```bash
   streamlit run app\s_app.py
   ```
   Then open the URL Streamlit (usually `http://localhost:8501/`) in your browser.

## Attribution & contact

Prototype prepared for the research paper: _Stateful Hash-Based Signature Scheme for Long-Term Document Storage_  
Authors: Vidhi Bhutia and Shayaree Lodh.
