import hashlib
import ecdsa
import json
import os

DB_FILE = "blockchain.json"

def print_db_sha256():
    """Print the SHA256 hash of the current blockchain JSON file (for tamper check)"""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "rb") as file:
            db_bytes = file.read()
        db_sha = hashlib.sha256(db_bytes).hexdigest()
        print(f"Current database SHA256: {db_sha}")
    else:
        print(f"Database file {DB_FILE} does not exist, unable to get SHA256.")

class Wallet:
    """Wallet for ECDSA key management and signatures"""
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.signing_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
        else:
            # Generate new private key (random)
            self.signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.verifying_key = self.signing_key.get_verifying_key()

    def get_private_key(self):
        """Return private key in hex string"""
        return self.signing_key.to_string().hex()

    def get_public_key(self):
        """Return public key in hex string"""
        return self.verifying_key.to_string().hex()

    def sign(self, content: bytes):
        """Sign content with private key, return hex string of signature"""
        return self.signing_key.sign(content).hex()

    @staticmethod
    def verify(content: bytes, signature_hex: str, public_key_hex: str):
        """Verify a signature for a message with the given public key"""
        try:
            verifying_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
            return verifying_key.verify(bytes.fromhex(signature_hex), content)
        except Exception:
            return False

class Block:
    """A block (record) in the blockchain"""
    def __init__(self, data, previous_hash, block_hash, signature, public_key):
        self.data = data
        self.previous_hash = previous_hash
        self.hash = block_hash
        self.signature = signature
        self.public_key = public_key

    def is_signature_valid(self):
        """Check the signature validity of the block"""
        return Wallet.verify(self.hash.encode(), self.signature, self.public_key)

    def calculate_hash(self):
        """Recalculate the hash of this block (should match self.hash)"""
        hasher = hashlib.sha256()
        hasher.update((str(self.data) + str(self.previous_hash)).encode())
        return hasher.hexdigest()

    def display(self, index):
        """Display block content and verification info"""
        print(f"Block {index}:")
        print(f" Data:\n{self.data}")
        print(f" Previous Block Hash : {self.previous_hash}")
        print(f" Current Hash       : {self.hash}")
        print(f" Signature          : {self.signature}")
        print(f" Public Key         : {self.public_key}")
        print(f" Signature Valid    : {self.is_signature_valid()}")
        print('-'*60)

class BlockchainDatabase:
    """Blockchain database using local JSON file"""
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        # If file does not exist, create an empty blockchain file
        if not os.path.exists(self.db_file):
            with open(self.db_file, "w", encoding="utf8") as file:
                json.dump([], file)

    def get_blocks(self):
        """Load all blocks from the JSON database file"""
        with open(self.db_file, "r", encoding="utf8") as file:
            records = json.load(file)
        blocks = []
        for record in records:
            block = Block(record['data'], record['previous_hash'], record['hash'],
                          record['signature'], record['public_key'])
            blocks.append(block)
        return blocks

    def add_block(self, block):
        """Append a new block to the JSON database file"""
        with open(self.db_file, "r", encoding="utf8") as file:
            records = json.load(file)
        records.append({
            'data': block.data,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'signature': block.signature,
            'public_key': block.public_key,
        })
        with open(self.db_file, "w", encoding="utf8") as file:
            json.dump(records, file, ensure_ascii=False, indent=2)

def print_menu():
    """Show main menu in console"""
    print("""
========== Personal Blockchain Record System (JSON Storage) ==========
1. Create New Wallet (Generate private key, public key)
2. Import Private Key
3. Show Current Public Key
4. Add Record (multiline, END to end)
5. Display All Blockchain Records
6. Verify Blockchain Integrity
7. Exit
8. Search Blocks Signed by Specific Public Key
=======================================================================
""")

def create_block(data, previous_hash, wallet):
    """Create a new block: compute its hash and sign it with the wallet"""
    hasher = hashlib.sha256()
    hasher.update((str(data) + str(previous_hash)).encode())
    block_hash = hasher.hexdigest()
    signature = wallet.sign(block_hash.encode())
    public_key = wallet.get_public_key()
    return Block(data, previous_hash, block_hash, signature, public_key)

def verify_chain(blocks):
    """Verify all signatures, hashes and blockchain linkage in sequence"""
    if not blocks:
        print("Blockchain is empty.")
        return False
    for idx in range(len(blocks)):
        block = blocks[idx]
        # Signature check
        if not block.is_signature_valid():
            print(f"Signature verification failed at block {idx}")
            return False
        # Chain linkage check
        if idx > 0:
            if block.previous_hash != blocks[idx - 1].hash:
                print(f"Blockchain link broken at block {idx}")
                return False
        # Hash recalc check
        if block.hash != block.calculate_hash():
            print(f"Block hash mismatch at block {idx}")
            return False
    return True

def main():
    print_db_sha256()  # Print db hash at startup
    wallet = None
    db = BlockchainDatabase()
    while True:
        print_menu()
        try:
            command = input("Please select a menu option (1-8): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nProgram exited.")
            break
        # Option 1: Generate new wallet
        if command == "1":
            wallet = Wallet()
            print("A new wallet has been generated.")
            print("Private Key (hex):", wallet.get_private_key())
            print("Please backup your private key safely!")
            print("Public Key (hex):", wallet.get_public_key())
        # Option 2: Import private key
        elif command == "2":
            private_key = input("Please enter private key (hex): ").strip()
            try:
                wallet = Wallet(private_key)
                print("Private key imported successfully. Public Key (hex):", wallet.get_public_key())
            except Exception as error:
                print("Failed to import private key. Check format.", str(error))
        # Option 3: Show current public key
        elif command == "3":
            if wallet:
                print("Current wallet public key (hex):", wallet.get_public_key())
            else:
                print("Please create or import a wallet first.")
        # Option 4: Add new record (multiline)
        elif command == "4":
            if not wallet:
                print("Please create or import a wallet first.")
                continue
            print("Enter your record content (multiline supported, END to finish):")
            lines = []
            while True:
                try:
                    line = input()
                except (KeyboardInterrupt, EOFError):
                    print("Input interrupted.")
                    lines = []
                    break
                if line.strip() == "END":
                    break
                lines.append(line)
            if not lines:
                print("No content added.")
                continue
            content = "\n".join(lines)
            blocks = db.get_blocks()
            previous_hash = blocks[-1].hash if blocks else '0' * 64
            new_block = create_block(content, previous_hash, wallet)
            db.add_block(new_block)
            print("Record has been added to blockchain and saved to JSON database.")
        # Option 5: Display all blocks
        elif command == "5":
            blocks = db.get_blocks()
            print(f"Total records: {len(blocks)}")
            for i, block in enumerate(blocks):
                block.display(i)
        # Option 6: Chain integrity check
        elif command == "6":
            blocks = db.get_blocks()
            if verify_chain(blocks):
                print("Blockchain integrity verified: No tampering, no break, all signatures valid.")
        # Option 7: Exit
        elif command == "7":
            print("Exited.")
            break
        # Option 8: Query by public key
        elif command == "8":
            public_key = input("Please enter the public key for query (hex): ").strip()
            blocks = db.get_blocks()
            if not verify_chain(blocks):
                print("Chain verification failed, terminating query.")
                continue
            found = False
            for idx, block in enumerate(blocks):
                if block.public_key == public_key:
                    print(f"★ Block signed by this public key ({public_key}):")
                    block.display(idx)
                    found = True
            if not found:
                print("No block found signed by this public key.")
        else:
            print("Invalid input, please try again.")
if __name__ == '__main__':
    main()
