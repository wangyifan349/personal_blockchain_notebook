"""
secure_chain_chat.py

Core Logic and Design Overview
-----------------------------

This program implements a secure, multi-user, chain-structured chat message system 
using a portable SQLite database. The core features are:

1. **Identity and Key Management**: 
   - Each user owns an ECDSA (secp256k1) signing key pair.
   - Public keys are shared and referenced for authentication and message addressing.

2. **Ephemeral Shared Secrets**:
   - For every user pair, a shared secret is established (e.g., via ECDH or pre-shared),
   - Message encryption keys are derived from this shared secret and a random salt per message.

3. **Confidentiality**:
   - Each message is encrypted with AES-GCM using a per-message symmetric key derived via HKDF using the shared secret and salt.
   - The system supports message confidentiality even if the database file is leaked.

4. **Message Chain Structure/Anti-Tamper**:
   - Every message record stores the SHA-256 hash of the ciphertext of the previous message (previous_hash).
   - The list of messages, linked via these hashes, forms a tamper-evident chain.
   - Any deletion or insertion (except for the very last message) breaks the chain and is immediately detectable.

5. **Authentication/Anti-Impersonation**: 
   - Each message record is signed with the sender's private key (ECDSA).
   - Verifiers can validate that the message was truly created by a user possessing the corresponding private key.
   - This ensures authenticity and prevents identity forgery.

6. **Menu-Driven Interface**:
   - Allows user identity creation/import/export.
   - Manages friends' public keys and shared secrets.
   - Multi-line message sending.
   - Complete chain validation, chain break detection, and message decryption.

All class, function, and variable names are fully spelled in standard English. 
All comments and docstrings are in English for maximum clarity and maintenance.

SQL statements are commented with explanations.

To use:
- Start by generating or importing your identity.
- Add friends' public keys.
- Set shared secrets for peer-to-peer communication.
- Use the menu to send and decrypt messages, or validate and check chain integrity.

"""

import os
import json
import base64
import time
import sqlite3
import hashlib
from typing import Dict, Tuple, List, Optional
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATABASE_FILE = "multi_user_chat.db"
IDENTITY_PRIVATE_KEY_FILE = "my_identity_private_key.txt"
FRIENDS_PUBLIC_KEYS_FILE = "friends_public_keys.json"
SHARED_SECRETS_FILE = "shared_secrets.json"

def encode_base64(data: bytes) -> str:
    """Encode bytes to a base64 string."""
    return base64.b64encode(data).decode('utf-8')

def decode_base64(data: str) -> bytes:
    """Decode a base64 string to bytes."""
    return base64.b64decode(data.encode('utf-8'))

def get_sha256_hex(data: bytes) -> str:
    """Compute SHA-256 as a hex digest of input bytes."""
    return hashlib.sha256(data).hexdigest()

class UserIdentity:
    """
    Manages a user's signing key (ECDSA), with export/import and public key access.
    """
    def __init__(self, signing_key: SigningKey):
        self.signing_key = signing_key
        self.verifying_key = signing_key.get_verifying_key()

    @classmethod
    def create_new_identity(cls) -> 'UserIdentity':
        """Generate a new secp256k1 signing key."""
        signing_key = SigningKey.generate(curve=SECP256k1)
        return cls(signing_key)

    @classmethod
    def import_identity_from_file(cls, file_path: str) -> 'UserIdentity':
        """Load signing key from a file."""
        with open(file_path, 'r') as file_handle:
            signing_key_hex = file_handle.read().strip()
            signing_key = SigningKey.from_string(bytes.fromhex(signing_key_hex), curve=SECP256k1)
            return cls(signing_key)

    def export_identity_to_file(self, file_path: str):
        """Export signing key to file."""
        with open(file_path, 'w') as file_handle:
            file_handle.write(self.signing_key.to_string().hex())

    def get_public_key_hex(self) -> str:
        """Get verifying (public) key as hex string."""
        return self.verifying_key.to_string().hex()

    @staticmethod
    def convert_public_key_hex_to_verifying_key(public_key_hex: str) -> VerifyingKey:
        """Convert hex-encoded public key to VerifyingKey object."""
        return VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)

def derive_symmetry_key_from_shared_secret(shared_secret: bytes, salt: bytes) -> bytes:
    """
    Derive a per-message AES key from a shared secret and per-message salt using HKDF.
    """
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"encrypted-message-key")
    return hkdf.derive(shared_secret)

def encrypt_plaintext_with_aesgcm(symmetry_key: bytes, plaintext: str) -> Tuple[str, str]:
    """
    Encrypt plaintext with AES-GCM.
    Returns ciphertext (base64) and nonce (base64).
    """
    aesgcm = AESGCM(symmetry_key)
    random_nonce = os.urandom(12)  # 96-bit random nonce
    ciphertext_bytes = aesgcm.encrypt(random_nonce, plaintext.encode(), None)
    return encode_base64(ciphertext_bytes), encode_base64(random_nonce)

def decrypt_ciphertext_with_aesgcm(symmetry_key: bytes, ciphertext_base64: str, nonce_base64: str) -> str:
    """
    Decrypt AES-GCM ciphertext using the given key/nonce.
    """
    aesgcm = AESGCM(symmetry_key)
    try:
        plaintext_bytes = aesgcm.decrypt(decode_base64(nonce_base64), decode_base64(ciphertext_base64), None)
        return plaintext_bytes.decode()
    except Exception:
        return "<decryption_failed>"

def initialize_database():
    """
    Create SQLite database and table structure for chain storage.
    """
    with sqlite3.connect(DATABASE_FILE) as connection:
        # Creating the message chain table.
        # Each message stores: index, timestamp, sender/receiver public keys, a random salt, 
        # ciphertext, the encryption nonce, the previous message's ciphertext hash, and the sender's signature.
        connection.execute(
            '''CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,              -- unique id in database
                message_index INTEGER,                              -- message serial index in the chain
                timestamp INTEGER,                                  -- unix timestamp when added
                sender_public_key TEXT,                             -- sender's public key (hex)
                receiver_public_key TEXT,                           -- receiver's public key (hex)
                salt TEXT,                                          -- per-message salt for encryption key (base64)
                ciphertext TEXT,                                    -- encrypted message (base64)
                nonce TEXT,                                         -- AES-GCM nonce (base64)
                previous_hash TEXT,                                 -- SHA256 hex of previous message's ciphertext
                signature TEXT                                      -- signature over message fields (base64)
            )'''
        )
        connection.commit()

def write_message_to_database(
    database_file: str,
    message_index: int,
    sender_identity: UserIdentity,
    receiver_public_key_hex: str,
    message_plaintext: str,
    previous_hash: str,
    shared_secret_bytes: bytes
) -> None:
    """
    Encrypt and sign the message, then store in the database as the next chain element.
    """
    random_salt = os.urandom(16)
    symmetry_key = derive_symmetry_key_from_shared_secret(shared_secret_bytes, random_salt)
    ciphertext_base64, nonce_base64 = encrypt_plaintext_with_aesgcm(symmetry_key, message_plaintext)
    timestamp_value = int(time.time())
    sender_public_key_hex = sender_identity.get_public_key_hex()
    message_payload = {
        "message_index": message_index,
        "timestamp": timestamp_value,
        "sender_public_key": sender_public_key_hex,
        "receiver_public_key": receiver_public_key_hex,
        "salt": encode_base64(random_salt),
        "ciphertext": ciphertext_base64,
        "nonce": nonce_base64,
        "previous_hash": previous_hash
    }
    # Sign the JSON-serialized message fields with the sender's private key.
    signature_str = encode_base64(sender_identity.signing_key.sign(json.dumps(message_payload, sort_keys=True).encode()))
    with sqlite3.connect(database_file) as connection:
        # Insert the message record into the messages table.
        connection.execute('''
            INSERT INTO messages
                (message_index, timestamp, sender_public_key, receiver_public_key, salt, ciphertext, nonce, previous_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                message_index, timestamp_value, sender_public_key_hex, receiver_public_key_hex,
                encode_base64(random_salt), ciphertext_base64, nonce_base64, previous_hash, signature_str,
            )
        )
        connection.commit()

def fetch_all_message_rows(database_file: str):
    """
    Fetch all messages sorted by chain order.
    """
    with sqlite3.connect(database_file) as connection:
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM messages ORDER BY message_index ASC')  # Ordered chain query.
        message_rows = cursor.fetchall()
    return message_rows

def get_next_message_index_and_previous_hash(database_file: str) -> Tuple[int, str]:
    """
    Get the index and prev_hash for the next message to be appended to the chain.
    """
    message_rows = fetch_all_message_rows(database_file)
    if not message_rows:
        return 0, "genesis"  # Chain genesis block.
    last_row = message_rows[-1]
    last_message_index = last_row[1]
    last_ciphertext_base64 = last_row[6]
    last_hash = get_sha256_hex(decode_base64(last_ciphertext_base64))
    return last_message_index + 1, last_hash

def check_message_chain_integrity(database_file: str) -> bool:
    """
    Validate the entire chain: signature verification and hash-link validation.
    Detects any tampering (modification or unauthorized insertion).
    """
    message_rows = fetch_all_message_rows(database_file)
    expected_previous_hash = None
    complete_integrity_check = True

    for row_index, message_row in enumerate(message_rows):
        (
            unused_id, message_index, timestamp, sender_public_key_hex, receiver_public_key_hex, salt,
            ciphertext, nonce, previous_hash, signature
        ) = message_row

        message_payload = {
            "message_index": message_index,
            "timestamp": timestamp,
            "sender_public_key": sender_public_key_hex,
            "receiver_public_key": receiver_public_key_hex,
            "salt": salt,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "previous_hash": previous_hash
        }
        verifying_key = UserIdentity.convert_public_key_hex_to_verifying_key(sender_public_key_hex)
        try:
            # Verify the digital signature using the stated public key.
            verifying_key.verify(decode_base64(signature), json.dumps(message_payload, sort_keys=True).encode())
        except Exception:
            print(f"X: Signature INVALID for message at index: {message_index}")
            complete_integrity_check = False
        if row_index == 0:
            if previous_hash != "genesis":
                print(f"X: First message INVALID (previous_hash != genesis)")
                complete_integrity_check = False
        else:
            if previous_hash != expected_previous_hash:
                print(f"X: Chain broken at message index: {message_index} (expected previous_hash: {expected_previous_hash[:12]}, actual: {previous_hash[:12]})")
                complete_integrity_check = False
        expected_previous_hash = get_sha256_hex(decode_base64(ciphertext))
    if complete_integrity_check:
        print("Chain complete and valid. All signatures verified successfully.")
    return complete_integrity_check

def detect_message_chain_breaks(database_file: str) -> None:
    """
    Output all breaks in the hash-link chain, i.e. missing or deleted messages (except for the chain tip).
    """
    message_rows = fetch_all_message_rows(database_file)
    expected_previous_hash = None
    for row_index, message_row in enumerate(message_rows):
        (
            unused_id, message_index, timestamp, sender_public_key_hex, receiver_public_key_hex, salt,
            ciphertext, nonce, previous_hash, signature
        ) = message_row

        if row_index == 0:
            if previous_hash != "genesis":
                print(f"Chain head missing (previous_hash is not genesis) at index = {message_index}")
            expected_previous_hash = get_sha256_hex(decode_base64(ciphertext))
        else:
            if previous_hash != expected_previous_hash:
                print(f"Broken chain or message missing at index = {message_index} (expected previous_hash: {expected_previous_hash[:12]}, actual: {previous_hash[:12]})")
            expected_previous_hash = get_sha256_hex(decode_base64(ciphertext))

def load_friends_public_keys() -> Dict[str, str]:
    """
    Load the dictionary mapping friend names to their public keys.
    """
    if os.path.exists(FRIENDS_PUBLIC_KEYS_FILE):
        with open(FRIENDS_PUBLIC_KEYS_FILE, "r") as file_handle:
            return json.load(file_handle)
    else:
        return {}

def save_friends_public_keys(friends: Dict[str, str]):
    """
    Save the dictionary of friend names and public keys.
    """
    with open(FRIENDS_PUBLIC_KEYS_FILE, "w") as file_handle:
        json.dump(friends, file_handle)

def load_shared_secrets() -> Dict[Tuple[str, str], bytes]:
    """
    Load user's shared secrets for every friend (public key tuple => secret bytes).
    """
    if os.path.exists(SHARED_SECRETS_FILE):
        with open(SHARED_SECRETS_FILE, "r") as file_handle:
            shared_content = json.load(file_handle)
        # Dictionary keys are stringified tuples, convert back to tuples
        return {tuple(key): decode_base64(val) for key, val in shared_content.items()}
    else:
        return {}

def save_shared_secrets(secrets: Dict[Tuple[str, str], bytes]):
    """
    Serializable save of all shared secrets (base64 values, tuple-keys stringified).
    """
    serialized_content = {str(list(key_tuple)): encode_base64(secret_bytes) for key_tuple, secret_bytes in secrets.items()}
    with open(SHARED_SECRETS_FILE, "w") as file_handle:
        json.dump(serialized_content, file_handle)

def decrypt_all_messages_for_identity(database_file: str, identity: UserIdentity, shared_secrets: Dict[Tuple[str, str], bytes]):
    """
    Decrypt and print all messages sent to or from the user, using only secrets available to him.
    """
    message_rows = fetch_all_message_rows(database_file)
    my_public_key = identity.get_public_key_hex()
    has_message = False
    for message_row in message_rows:
        (
            unused_id, message_index, timestamp, sender_public_key_hex, receiver_public_key_hex, salt_base64,
            ciphertext_base64, nonce_base64, previous_hash, signature
        ) = message_row

        shared_secret_key: Optional[Tuple[str, str]] = None
        if sender_public_key_hex == my_public_key:
            shared_secret_key = (sender_public_key_hex, receiver_public_key_hex)
        elif receiver_public_key_hex == my_public_key:
            shared_secret_key = (sender_public_key_hex, receiver_public_key_hex)
        else:
            continue
        shared_secret_bytes = shared_secrets.get(shared_secret_key)
        if not shared_secret_bytes:
            print(f"Message {message_index} missing shared_secret, cannot decrypt.")
            continue
        encrypted_message_key = derive_symmetry_key_from_shared_secret(shared_secret_bytes, decode_base64(salt_base64))
        plaintext = decrypt_ciphertext_with_aesgcm(encrypted_message_key, ciphertext_base64, nonce_base64)
        print(f"\n*Index: {message_index} | From: {sender_public_key_hex[:10]} | To: {receiver_public_key_hex[:10]} | Time: {time.ctime(timestamp)}")
        print(f"{plaintext}\n------------------------------------")
        has_message = True
    if not has_message:
        print("No messages available for decryption.")

def print_main_menu():
    """Print main menu options for the chat system."""
    print("""
========= Secure Chat Menu =========
1. Show my identity public key
2. Export my identity to file
3. Import identity from file
4. Add friend public key
5. List friends
6. Add shared secret for friend
7. List shared secrets
8. Send message (multi-line, END to finish)
9. Decrypt all my messages
10. Check chain integrity (detect tampering)
11. Detect message chain breaks (detect deletion)
12. Exit
=============================
""")

def main():
    # Startup: create database and try to load or create an identity.
    initialize_database()
    if os.path.exists(IDENTITY_PRIVATE_KEY_FILE):
        user_identity = UserIdentity.import_identity_from_file(IDENTITY_PRIVATE_KEY_FILE)
    else:
        user_identity = UserIdentity.create_new_identity()
        user_identity.export_identity_to_file(IDENTITY_PRIVATE_KEY_FILE)
        print(f"Your new identity private key has been saved as {IDENTITY_PRIVATE_KEY_FILE}")
    friends_public_keys = load_friends_public_keys()
    shared_secrets = load_shared_secrets()

    while True:
        print_main_menu()
        selected_option = input("Please select an option number > ").strip()
        if selected_option == "1":
            print(f"Your public key:\n{user_identity.get_public_key_hex()}")
        elif selected_option == "2":
            filename = input("Enter the file name to export your identity > ")
            user_identity.export_identity_to_file(filename)
            print(f"Export successful to {filename}")
        elif selected_option == "3":
            filename = input("Enter your identity private key file name > ")
            try:
                user_identity = UserIdentity.import_identity_from_file(filename)
                user_identity.export_identity_to_file(IDENTITY_PRIVATE_KEY_FILE)
                print("Successfully loaded and switched current identity.")
            except Exception as exception_object:
                print("Failed to load identity:", exception_object)
        elif selected_option == "4":
            friend_nickname = input("Enter your friend's nickname (unique, used for identification) > ").strip()
            friend_public_key = input("Enter your friend's public key (hexadecimal string) > ").strip()
            friends_public_keys[friend_nickname] = friend_public_key
            save_friends_public_keys(friends_public_keys)
            print("Friend's public key has been added.")
        elif selected_option == "5":
            if not friends_public_keys:
                print("No friends found.")
            else:
                for friend_nickname, public_key in friends_public_keys.items():
                    print(f"{friend_nickname}: {public_key}")
        elif selected_option == "6":
            if not friends_public_keys:
                print("Please add a friend first.")
                continue
            selected_friend = input("Which friend do you want to add a shared secret for (nickname) > ").strip()
            if selected_friend not in friends_public_keys:
                print("Friend does not exist.")
                continue
            print('''Enter the pre-agreed shared secret, which both parties must keep consistent.
(32 bytes Base64 string or 64-character hexadecimal string is recommended)''')
            secret_input = input("Shared secret > ").strip()
            if all(character in "0123456789abcdefABCDEF" for character in secret_input) and len(secret_input) == 64:
                shared_secret_bytes = bytes.fromhex(secret_input)
            else:
                try:
                    shared_secret_bytes = decode_base64(secret_input)
                except:
                    print("Invalid format.")
                    continue
            my_public_key_hex = user_identity.get_public_key_hex()
            friend_public_key_hex = friends_public_keys[selected_friend]
            shared_key1 = (my_public_key_hex, friend_public_key_hex)
            shared_key2 = (friend_public_key_hex, my_public_key_hex)
            shared_secrets[shared_key1] = shared_secret_bytes
            shared_secrets[shared_key2] = shared_secret_bytes
            save_shared_secrets(shared_secrets)
            print("Shared secret set successfully.")
        elif selected_option == "7":
            if not shared_secrets:
                print("No shared secrets found.")
            else:
                for key_tuple, secret_bytes in shared_secrets.items():
                    print(f"{key_tuple}: {encode_base64(secret_bytes)}")
        elif selected_option == "8":
            if not friends_public_keys or not shared_secrets:
                print("Please configure your friends and the corresponding shared secret first.")
                continue
            friend_selected_nickname = input("Send message to which friend (nickname) > ").strip()
            if friend_selected_nickname not in friends_public_keys:
                print("Friend not found.")
                continue
            friend_public_key_hex = friends_public_keys[friend_selected_nickname]
            shared_secret_key_tuple = (user_identity.get_public_key_hex(), friend_public_key_hex)
            if shared_secret_key_tuple not in shared_secrets:
                print("No configured shared secret for this friend.")
                continue
            shared_secret_bytes = shared_secrets[shared_secret_key_tuple]
            print("Enter multi-line message. Enter 'END' alone on a line to finish >")
            lines: List[str] = []
            while True:
                line_input = input()
                if line_input == "END":
                    break
                lines.append(line_input)
            message_plaintext = "\n".join(lines)
            next_message_index, next_previous_hash = get_next_message_index_and_previous_hash(DATABASE_FILE)
            write_message_to_database(DATABASE_FILE, next_message_index, user_identity, friend_public_key_hex, message_plaintext, next_previous_hash, shared_secret_bytes)
            print("Message saved! (Exchange your db file with friends for message sync.)")
        elif selected_option == "9":
            decrypt_all_messages_for_identity(DATABASE_FILE, user_identity, shared_secrets)
        elif selected_option == "10":
            check_message_chain_integrity(DATABASE_FILE)
        elif selected_option == "11":
            detect_message_chain_breaks(DATABASE_FILE)
        elif selected_option == "12":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please select again.")

if __name__ == "__main__":
    main()
