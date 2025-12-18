# File dari sisi client
# Client bertugas membuat private & public key,
# serta menandatangani pesan sebelum dikirim ke server

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

# 1. PEMBUATAN PRIVATE & PUBLIC KEY

priv_key = ed25519.Ed25519PrivateKey.generate()

pub_key = priv_key.public_key()


with open("user_private_key.pem", "wb") as f:
    f.write(
        priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("user_public_key.pem", "wb") as f:
    f.write(
        pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("[OK] Private & Public key berhasil dibuat")

# 2. PEMBUATAN PESAN RAHASIA

message = "hello world"
message_bytes = message.encode()

# 3. PENANDATANGANAN PESAN (DIGITAL SIGNATURE)

signature = priv_key.sign(message_bytes)

signature_b64 = base64.b64encode(signature).decode()

print("\nMessage:")
print(message)

print("\nSignature (base64):")
print(signature_b64)

# 4. OUTPUT UNTUK DIGUNAKAN DI SWAGGER

print("\nGunakan data berikut di endpoint /verify:")
print("username      : (sesuai username saat upload public key)")
print("message       :", message)
print("signature     :", signature_b64)