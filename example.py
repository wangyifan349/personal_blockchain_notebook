from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
# ---- 1. Digital Signature and Verification (Ed25519) ----
# Generate private and public key pair
private_key = ECC.generate(curve='ed25519')
public_key = private_key.public_key()
# Original message
message = b'hello, pycryptodome digital signature!'
# Sign the message
signer = eddsa.new(private_key, 'rfc8032')
signature = signer.sign(message)
print("Signature(hex):", signature.hex())
# Verify the signature
verifier = eddsa.new(public_key, 'rfc8032')
try:
    verifier.verify(message, signature)
    print("Signature verification succeeded!")
except ValueError:
    print("Signature verification failed!")
# ---- 2. ChaCha20-Poly1305 Encryption and Decryption ----
# Generate random key and nonce
key = get_random_bytes(32)      # Must be 32 bytes
nonce = get_random_bytes(12)    # Must be 12 bytes
plaintext = b'hello, pycryptodome chacha20-poly1305!'
aad = b'optional-header-data'   # Optional Additional Authenticated Data
# Encryption
cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
cipher.update(aad)   # Set AAD, optional
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
print("Ciphertext(hex):", ciphertext.hex())
print("Auth Tag(hex):", tag.hex())
print("Nonce(hex):", nonce.hex())
# Decryption
try:
    cipher_dec = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
    print("Decryption succeeded, plaintext:", decrypted)
except ValueError:
    print("Ciphertext or authentication failed, decryption error!")
