"""
https://github.com/warner/python-ecdsa
"""



from ecdsa import SigningKey, SECP256k1, BadSignatureError

# 1. Generate ECDSA (SECP256k1) key pair
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.get_verifying_key()

# 2. Message to be signed
message = b"This is a signature demo using SECP256k1 curve."

# 3. Sign the message
signature = private_key.sign(message)
print("Signature (hex):", signature.hex())

# 4. Verify the signature
try:
    valid = public_key.verify(signature, message)
    print("Signature is VALID.")
except BadSignatureError:
    print("Signature is INVALID.")

# 5. Show public/private key (hex)
print("\nPublic Key (compressed hex):", public_key.to_string('compressed').hex())
print("Private Key (hex):", private_key.to_string().hex())
