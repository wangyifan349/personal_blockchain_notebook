import hashlib
import ecdsa
import sqlite3
import os

DB_PATH = "blockchain.db"

def print_db_sha256():
    """
    Print the SHA256 hash of the database file on program startup.
    """
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "rb") as f:
            db_bytes = f.read()
            sha = hashlib.sha256(db_bytes).hexdigest()
            print(f"Current DB SHA256: {sha}")
    else:
        print(f"Database file {DB_PATH} does not exist, SHA256 unavailable.")

class Wallet:
    """
    Wallet class for managing private/public keys and signatures.
    """
    def __init__(self, privkey_hex=None):
        if privkey_hex:
            self.sk = ecdsa.SigningKey.from_string(bytes.fromhex(privkey_hex), curve=ecdsa.SECP256k1)
        else:
            self.sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.vk = self.sk.get_verifying_key()
    def get_private_key(self):
        return self.sk.to_string().hex()
    def get_public_key(self):
        return self.vk.to_string().hex()
    def sign(self, content: bytes):
        return self.sk.sign(content).hex()
    @staticmethod
    def verify(content: bytes, sig_hex: str, pub_hex: str):
        try:
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pub_hex), curve=ecdsa.SECP256k1)
            return vk.verify(bytes.fromhex(sig_hex), content)
        except Exception:
            return False

class Block:
    """
    Block class, representing a single blockchain record.
    """
    def __init__(self, data, prev_hash, block_hash, sign, pubkey):
        self.data = data
        self.prev_hash = prev_hash
        self.hash = block_hash
        self.sign = sign
        self.pubkey = pubkey

    def is_signature_valid(self):
        return Wallet.verify(self.hash.encode(), self.sign, self.pubkey)

    def calc_hash(self):
        hasher = hashlib.sha256()
        hasher.update((str(self.data)+str(self.prev_hash)).encode())
        return hasher.hexdigest()

    def display(self, index):
        print(f"Block {index}:")
        print(f"  data      :\n{self.data}")
        print(f"  prev_hash : {self.prev_hash}")
        print(f"  hash      : {self.hash}")
        print(f"  signature : {self.sign}")
        print(f"  pubkey    : {self.pubkey}")
        print(f"  signature valid : {self.is_signature_valid()}")
        print('-'*60)

class ChainDB:
    """
    Blockchain database handler with SQLite backend.
    """
    def __init__(self, db_path=DB_PATH):
        self.conn = sqlite3.connect(db_path)
        self.init_db()
    def init_db(self):
        cur = self.conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT,
                prev_hash TEXT,
                hash TEXT,
                sign TEXT,
                pubkey TEXT
            )
        ''')
        self.conn.commit()
    def get_blocks(self):
        """Fetch all blocks in order from the database"""
        cur = self.conn.cursor()
        cur.execute('SELECT data, prev_hash, hash, sign, pubkey FROM blocks ORDER BY id ASC')
        rows = cur.fetchall()
        blocks = []
        for row in rows:
            block = Block(row[0], row[1], row[2], row[3], row[4])
            blocks.append(block)
        return blocks
    def add_block(self, block):
        """Add a new block to the database"""
        cur = self.conn.cursor()
        cur.execute('INSERT INTO blocks (data, prev_hash, hash, sign, pubkey) VALUES (?, ?, ?, ?, ?)',
                    (block.data, block.prev_hash, block.hash, block.sign, block.pubkey))
        self.conn.commit()

def menu():
    """
    Main menu interface.
    """
    print("""
=========== Personal Blockchain Record System (with SQLite3) ===========
1. Create new wallet (private/public key)
2. Import private key
3. Show current public key
4. Add a record (multi-line, end with END)
5. Show all blockchain records
6. Verify blockchain integrity
7. Exit
8. Query all blocks signed by a specific public key
9. Fuzzy body search on all blocks using LCS (Longest Common Subsequence)
==========================================================================
""")

def create_block(data, prev_hash, wallet):
    """
    Create a new block, automatically computing hash and signature.
    """
    hasher = hashlib.sha256()
    hasher.update((str(data)+str(prev_hash)).encode())
    block_hash = hasher.hexdigest()
    sign = wallet.sign(block_hash.encode())
    pubkey = wallet.get_public_key()
    return Block(data, prev_hash, block_hash, sign, pubkey)

def longest_common_subsequence(a, b):
    """
    Return the length of the longest common subsequence of string a and b.
    """
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            if a[i] == b[j]:
                dp[i+1][j+1] = dp[i][j] + 1
            else:
                dp[i+1][j+1] = max(dp[i][j+1], dp[i+1][j])
    return dp[m][n]

def check_chain(blocks):
    """
    Verify whole chain for signature, hash, and linkage validity.
    """
    if not blocks:
        print("Blockchain is empty.")
        return False
    for idx in range(len(blocks)):
        block = blocks[idx]
        # Signature validity
        if not block.is_signature_valid():
            print("Signature validation failed at block {}".format(idx))
            return False
        # Chain linkage validity
        if idx > 0:
            if block.prev_hash != blocks[idx-1].hash:
                print("Blockchain linkage broken at block {}".format(idx))
                return False
        # Hash correctness
        if block.hash != block.calc_hash():
            print("Hash mismatch at block {}".format(idx))
            return False
    return True

def main():
    print_db_sha256()   # Print SHA256 of the database file at startup
    wallet = None
    db = ChainDB()
    while True:
        menu()
        try:
            cmd = input("Please select a menu option (1-9): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nProgram exited.")
            break
        if cmd == "1":
            wallet = Wallet()
            print("New wallet created.")
            print("Private key (hex):", wallet.get_private_key())
            print("Please backup this private key in a secure location!")
            print("Public key (hex):", wallet.get_public_key())
        elif cmd == "2":
            priv = input("Enter private key in hex: ").strip()
            try:
                wallet = Wallet(priv)
                print("Private key imported. Public key (hex):", wallet.get_public_key())
            except Exception as e:
                print("Private key import failed. Check the format.", str(e))
        elif cmd == "3":
            if wallet:
                print("Current wallet public key (hex):", wallet.get_public_key())
            else:
                print("Please create or import a wallet first.")
        elif cmd == "4":
            if not wallet:
                print("Please create or import a wallet first.")
                continue
            print("Enter your record content, multi-line is supported (end with END):")
            lines = []
            while True:
                try:
                    line = input()
                except (KeyboardInterrupt, EOFError):
                    print("Input aborted.")
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
            if len(blocks) > 0:
                prev_hash = blocks[-1].hash
            else:
                prev_hash = '0'*64
            new_block = create_block(content, prev_hash, wallet)
            db.add_block(new_block)
            print("Record added to blockchain and stored in SQLite3 database.")
        elif cmd == "5":
            blocks = db.get_blocks()
            print(f"Total records: {len(blocks)}")
            for i in range(len(blocks)):
                blocks[i].display(i)
        elif cmd == "6":
            blocks = db.get_blocks()
            if check_chain(blocks):
                print("Blockchain integrity verified: no tampering, no breakage, all signatures valid.")
        elif cmd == "7":
            print("Exited.")
            break
        elif cmd == "8":
            # Query all blocks signed with a specific pubkey (check chain first)
            pubkey = input("Enter the public key (hex) to query: ").strip()
            blocks = db.get_blocks()
            if not check_chain(blocks):
                print("Chain validation failed; query aborted.")
                continue
            found = False
            for idx in range(len(blocks)):
                block = blocks[idx]
                if block.pubkey == pubkey:
                    print(f"★Block signed by this public key ({pubkey}):")
                    block.display(idx)
                    found = True
            if not found:
                print("No blocks found for this public key.")
        elif cmd == "9":
            keyword = input("Enter keyword for LCS fuzzy search: ").strip()
            blocks = db.get_blocks()
            if not check_chain(blocks):
                print("Chain validation failed; search aborted.")
                continue
            score_blocks = []
            for idx in range(len(blocks)):
                block = blocks[idx]
                lcs = longest_common_subsequence(block.data, keyword)
                if lcs > 0:
                    score_blocks.append((lcs, idx, block))
            # descending sort
            score_blocks.sort(key=lambda x: (-x[0], x[1]))
            if len(score_blocks) == 0:
                print("No relevant blocks found.")
            else:
                print(f'Blocks related to "{keyword}", sorted by LCS length (descending):')
                for sb in score_blocks:
                    print(f'[LCS length: {sb[0]}]')
                    sb[2].display(sb[1])
        else:
            print("Invalid input, please try again.")

if __name__ == '__main__':
    main()
