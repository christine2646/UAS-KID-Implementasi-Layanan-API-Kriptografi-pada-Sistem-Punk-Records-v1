from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os, uuid, base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

app = FastAPI(title="Security Service", version="1.0.0")

sessions = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def index():
    return {"message": "Security Service running. Visit /docs"}

@app.get("/health")
async def health():
    return {
        "status": "OK",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="File harus PDF")

    os.makedirs("uploaded_files", exist_ok=True)

    contents = await file.read()
    with open(f"uploaded_files/{file.filename}", "wb") as f:
        f.write(contents)

    return {"message": "PDF berhasil diupload"}

@app.post("/store")
async def store_pubkey(username: str, pubkey: UploadFile = File(...)):
    contents = await pubkey.read()

    if not contents:
        raise HTTPException(status_code=400, detail="Public key kosong")

    serialization.load_pem_public_key(contents)

    os.makedirs("data", exist_ok=True)

    with open(f"data/{username}_pubkey.pem", "wb") as f:
        f.write(contents)

    return {
        "message": "Public key berhasil disimpan",
        "username": username,
        "algorithm": "ed25519"
    }

@app.post("/verify")
async def verify(username: str, message: str, signature: str):
    pubkey_path = f"data/{username}_pubkey.pem"

    if not os.path.exists(pubkey_path):
        return {"valid": False, "message": "Public key tidak ditemukan"}

    try:
        with open(pubkey_path, "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read())

        signature_bytes = base64.b64decode(signature)

        pubkey.verify(signature_bytes, message.encode())

        return {
            "valid": True,
            "message": "Signature valid",
            "algorithm": "ed25519"
        }

    except InvalidSignature:
        return {
            "valid": False,
            "message": "Signature tidak valid"
        }

    except Exception as e:
        return {
            "valid": False,
            "message": f"Error: {e}"
        }

@app.post("/login")
async def login(username: str):
    pubkey_path = f"data/{username}_pubkey.pem"

    if not os.path.exists(pubkey_path):
        return {"message": "User belum terdaftar"}

    token = str(uuid.uuid4())
    sessions[token] = username

    return {
        "message": "Login berhasil",
        "token": token
    }

@app.post("/relay")
async def relay(token: str, receiver: str, message: str):
    if token not in sessions:
        return {"message": "Unauthorized"}

    sender = sessions[token]

    os.makedirs("messages", exist_ok=True)

    with open(f"messages/{receiver}.txt", "a") as f:
        f.write(f"Dari {sender}: {message}\n")

    return {
        "message": "Pesan berhasil diteruskan",
        "from": sender,
        "to": receiver
    }
