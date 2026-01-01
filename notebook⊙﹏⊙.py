import sqlite3
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
import getpass

DB_FILENAME = 'notebook.db'
SALT_FILENAME = 'notebook.salt'

def get_key_from_password():
    # Ask user for password at startup
    password = getpass.getpass('Enter notebook password: ')
    # Generate or load salt
    if os.path.exists(SALT_FILENAME):
        with open(SALT_FILENAME, 'rb') as f:
            salt = f.read()
        if len(salt) != 16:
            raise ValueError("Salt size invalid!")
    else:
        salt = get_random_bytes(16)
        with open(SALT_FILENAME, 'wb') as f:
            f.write(salt)
    # Derive key (PBKDF2, 100k rounds)
    key = PBKDF2(password, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
    return key

key = get_key_from_password()

# SQLite setup
conn = sqlite3.connect(DB_FILENAME)
cur = conn.cursor()
cur.execute('''
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ciphertext BLOB NOT NULL,
    tag BLOB NOT NULL,
    nonce BLOB NOT NULL
)
''')
conn.commit()

# --- Write phase ---
print("Enter your notes (multi-line, type 'END' on a new line to finish one note, empty line to stop input):")

prev_cipher_hash = bytes(32)  # 32 zero bytes for first note

while True:
    lines = []
    while True:
        line = input()
        if line == "END":
            break
        if line == "":
            lines = []
            break
        lines.append(line)
    if not lines:
        break
    plaintext = ("\n".join(lines)).encode('utf-8')
    nonce = get_random_bytes(12)
    aad = prev_cipher_hash

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    cur.execute(
        "INSERT INTO notes (ciphertext, tag, nonce) VALUES (?, ?, ?)",
        (ciphertext, tag, nonce)
    )
    conn.commit()

    prev_cipher_hash = SHA256.new(ciphertext).digest()

print("\n--- All messages stored. Now reading and decrypting... ---\n")

# --- Tampering test (optional, can be removed or uncommented) ---
# tamper_id = 2
# cur.execute("UPDATE notes SET ciphertext = randomblob(length(ciphertext)) WHERE id = ?", (tamper_id,))
# conn.commit()

# --- Read phase ---
prev_cipher_hash = bytes(32)
cur.execute("SELECT id, ciphertext, tag, nonce FROM notes ORDER BY id ASC")
rows = cur.fetchall()

for idx, (rowid, ciphertext, tag, nonce) in enumerate(rows):
    aad = prev_cipher_hash
    cipher_dec = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher_dec.update(aad)
    try:
        decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
        print(f"Note {idx+1} (id={rowid}):\n{decrypted.decode('utf-8')}\n" + "-"*40)
    except ValueError:
        print(f"Tampering detected! Message authentication failed at note {idx+1} (id={rowid})")
        break
    prev_cipher_hash = SHA256.new(ciphertext).digest()

conn.close()
