import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

# ==========================================
# AES-256-GCM File Encryption/Decryption
# ==========================================
def generate_aes_key() -> bytes:
    """Generates a secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(file_path: str, aes_key: bytes, output_path: str = None) -> str:
    """Encrypts a file using AES-256-GCM."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce

    with open(file_path, "rb") as f:
        data = f.read()

    ct = aesgcm.encrypt(nonce, data, None)

    if output_path is None:
        output_path = os.path.join("encrypted", os.path.basename(file_path) + ".enc")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "wb") as f:
        f.write(nonce + ct)

    return output_path


def decrypt_file(encrypted_file_path: str, aes_key: bytes) -> str:
    """Decrypts a file using AES-256-GCM."""
    aesgcm = AESGCM(aes_key)
    with open(encrypted_file_path, "rb") as f:
        blob = f.read()

    nonce = blob[:12]
    ct = blob[12:]

    decrypted = aesgcm.decrypt(nonce, ct, None)

    output_path = os.path.join("decrypted", os.path.basename(encrypted_file_path).replace(".enc", ""))
    os.makedirs("decrypted", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(decrypted)

    return output_path


def compute_sha256(file_path: str) -> str:
    """Computes SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha.update(chunk)
    return sha.hexdigest()

# ==========================================
# RSA Hybrid Encryption
# ==========================================
def encrypt_key_rsa(aes_key: bytes, recipient_public_key) -> bytes:
    """Encrypts the AES key with recipient's RSA public key."""
    return recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_key_rsa(encrypted_key: bytes, recipient_private_key) -> bytes:
    """Decrypts the AES key using recipient's RSA private key."""
    return recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ==========================================
# Testing Area
# ==========================================
if __name__ == "__main__":
    print("--- 1. Setup Keys ---")
    aes_key = generate_aes_key()
    print("AES-256 Key generated.")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    print("\n--- 2. File Encryption ---")
    target_file = "text.txt"
    if not os.path.exists(target_file):
        print(f"Error: {target_file} not found.")
        exit()

    enc_file = encrypt_file(target_file, aes_key)
    print(f"File encrypted: {enc_file}")
    print(f"SHA256 Hash: {compute_sha256(enc_file)}")

    print("\n--- 3. Encrypt AES Key with RSA ---")
    enc_aes_key = encrypt_key_rsa(aes_key, public_key)
    print("AES Key encrypted with RSA.")

    print("\n--- 4. Decrypt AES Key ---")
    dec_aes_key = decrypt_key_rsa(enc_aes_key, private_key)
    assert aes_key == dec_aes_key, "Decrypted key does not match original!"
    print("AES Key successfully decrypted.")

    print("\n--- 5. File Decryption ---")
    dec_file = decrypt_file(enc_file, dec_aes_key)
    print(f"File decrypted: {dec_file}")

    with open(dec_file, "r") as f:
        print("Decrypted Content:\n", f.read())
