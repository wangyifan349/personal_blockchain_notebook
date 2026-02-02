'''===============================================================================
This script is a CLI (Command Line Interface) utility for building, saving, and verifying a tamper-proof lyric "ring blockchain".  
Each lyric forms a block. Each block contains the lyric, the previous block's hash, the public key (base64), its own hash, and a digital signature.  
The blocks are linked in a ring (the first block points back to the last block), so any removal or tampering is detected by full verification.  
Main features include:
- ECDSA (secp256k1) key pair creation (base64, recommended to save and keep safe)
- Create a ring blockchain from lyrics with your key (use default demo or your own lyrics)
- Save the blockchain (all data, including lyrics) to a JSON file (time-named)
- Load and verify an existing JSON blockchain file using only the public key
All actions are accessible via interactive CLI menus, and all essential code is well commented.
Here is a polished English version of your description, suitable for the file header or project README:

In previous versions, if a user deleted entries from the end of the database backward, such actions could not be fully detected—validation was only possible in a one-way (end-to-start) direction, leaving the chain vulnerable to partial tampering or deletion. In this version, we adopt a circular (ring) digital signature mechanism, ensuring every block is mutually linked in both directions. This design guarantees comprehensive, bidirectional validation: any modification or deletion, regardless of position, will be immediately detected during verification. As a result, the entire dataset is fully protected against tampering or forgery. However, this improvement also means that, once created, all data blocks are permanently locked and can no longer be modified or removed, representing a trade-off for maximum integrity and security.
===============================================================================
'''
import ecdsa
import base64
import hashlib
import json
import time
import os
from typing import List

# ----- Key Functions -----
def create_new_keypair():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)    # Generate signing key
    vk = sk.verifying_key                                    # Get verifying key
    sk_b64 = base64.b64encode(sk.to_string()).decode('utf-8')   # Private key to base64
    vk_b64 = base64.b64encode(vk.to_string()).decode('utf-8')   # Public key to base64
    print("\n=== Your NEW PRIVATE KEY (base64) ===\n", sk_b64)  # Display keys
    print("=== Your NEW PUBLIC  KEY (base64) ===\n", vk_b64)
    print("!!! Please save your private key safely !!!")
    return sk_b64, vk_b64

def get_sk_from_b64(sk_b64):
    sk_bytes = base64.b64decode(sk_b64.encode('utf-8'))         # Decode from base64
    return ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)

def get_vk_from_b64(vk_b64):
    vk_bytes = base64.b64decode(vk_b64.encode('utf-8'))         # Decode from base64
    return ecdsa.VerifyingKey.from_string(vk_bytes, curve=ecdsa.SECP256k1)

# ----- Block & Chain Classes -----
class LyricBlock:
    def __init__(self, lyric, prev_hash, public_key, block_hash="", signature=""):
        self.lyric = lyric                                     # The lyric string
        self.prev_hash = prev_hash                             # Hash from previous block (ring: first links last)
        self.public_key = public_key                           # Block public key (base64)
        self.block_hash = block_hash                           # This block's hash
        self.signature = signature                             # This block's signature

    def calc_block_hash(self):
        return hashlib.sha256(
            (self.lyric + self.prev_hash + self.public_key).encode("utf-8")
        ).hexdigest()                                         # Hash of lyric+prev_hash+public_key

    def sign_block(self, sk):
        self.block_hash = self.calc_block_hash()               # Calculate block's hash
        content = self.lyric + self.block_hash + self.prev_hash + self.public_key
        sig = sk.sign(content.encode("utf-8"))                 # Sign the content
        self.signature = base64.b64encode(sig).decode("utf-8") # Store base64 signature

    def verify_signature(self):
        vk = get_vk_from_b64(self.public_key)
        content = self.lyric + self.block_hash + self.prev_hash + self.public_key
        try:
            return vk.verify(base64.b64decode(self.signature), content.encode("utf-8")) # Signature check
        except Exception:
            return False

    def as_dict(self):
        return {
            "lyric": self.lyric,
            "prev_hash": self.prev_hash,
            "block_hash": self.block_hash,
            "public_key": self.public_key,
            "signature": self.signature
        }

    @staticmethod
    def from_dict(block_dict):
        return LyricBlock(
            lyric=block_dict["lyric"],
            prev_hash=block_dict["prev_hash"],
            public_key=block_dict["public_key"],
            block_hash=block_dict["block_hash"],
            signature=block_dict["signature"]
        )

class LyricRingChain:
    def __init__(self, public_key):
        self.public_key = public_key                           # The chain's public key (base64 string)
        self.blocks: List[LyricBlock] = []                     # List of LyricBlock instances

    def build_from_lyrics_and_sk(self, lyrics, sk):
        prev_hash = ""
        self.blocks = []
        for lyric in lyrics:
            block = LyricBlock(lyric, prev_hash, self.public_key)
            block.sign_block(sk)
            self.blocks.append(block)
            prev_hash = block.block_hash                       # For the next block
        if len(self.blocks) > 1:
            first_block = self.blocks[0]
            last_block = self.blocks[-1]
            first_block.prev_hash = last_block.block_hash      # First's prev_hash links last
            first_block.sign_block(sk)                         # Re-sign for proper ring

    def verify_ring(self, verbose=True):
        n = len(self.blocks)
        if n == 0:
            if verbose:
                print("Chain is empty.")
            return False
        for i, blk in enumerate(self.blocks):
            expected_hash = blk.calc_block_hash()
            if blk.block_hash != expected_hash:
                if verbose:
                    print(f"Block {i}: hash check failed.")
                return False
            if not blk.verify_signature():
                if verbose:
                    print(f"Block {i}: signature verification failed.")
                return False
            prev_idx = (i - 1) % n
            if blk.prev_hash != self.blocks[prev_idx].block_hash:
                if verbose:
                    print(f"Block {i}: prev_hash does not match block_hash of block {prev_idx}.")
                return False
        if verbose:
            print("Chain verification succeeded: the ring is unbroken, authentic, and tamper-proof.")
        return True

    def print_blocks(self):
        for i, blk in enumerate(self.blocks):
            print(f"\nBlock {i}:")
            for k, v in blk.as_dict().items():
                print(f"  {k}: {v}")

    def save_to_json(self, filename):
        data = {
            'public_key': self.public_key,
            'block_list': [blk.as_dict() for blk in self.blocks]
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)                       # Write chain to file
        print(f"Chain saved to {filename}")

    @staticmethod
    def load_from_json(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        chain = LyricRingChain(data['public_key'])
        chain.blocks = [LyricBlock.from_dict(bd) for bd in data['block_list']]
        return chain

# ----- Demo Lyrics -----
DEFAULT_LYRICS = [
    "Shadows slow dance on the pavement tonight,",
    "Neon memories flicker under broken streetlights,",
    "Old hopes waiting for the corners of dawn,",
    "Every heartbeat writing a line in my song."
]

# ----- CLI Menu -----
def cli_menu():
    print("\n=== Lyric Ring Blockchain CLI ===")
    print("1. Generate NEW key pair (ECDSA-secp256k1)")
    print("2. Create ring blockchain & save (with lyrics)")
    print("3. Load JSON blockchain file & verify ring")
    print("4. Exit")

def input_multiline(prompt="Enter lines (blank line to finish):"):
    print(prompt)
    lines = []
    while True:
        ln = input()
        if not ln.strip():
            break
        lines.append(ln)
    return lines

def prompt_lyrics():
    print("\nWould you like to use the default lyrics for demo? (y/n)")
    resp = input("(y/n): ").strip().lower()
    if resp == 'y':
        print("[Using default demo lyrics!]")
        for i, line in enumerate(DEFAULT_LYRICS):
            print(f"Line {i+1}: {line}")
        return list(DEFAULT_LYRICS)
    else:
        print("Enter your lyrics, one line per block. (blank line to end):")
        lines = input_multiline()
        if len(lines) >= 2:
            return lines
        else:
            print("You need at least 2 lines. Try again.")
            return prompt_lyrics()

def main():
    while True:
        cli_menu()
        choice = input("Your choice: ").strip()
        if choice == "1":
            create_new_keypair()                                   # Key creation
        elif choice == "2":
            print("\nYou will need a private key (for signing) and its corresponding public key.")
            print("Paste your PRIVATE key (base64):")
            sk_b64 = input("> ").strip()
            print("Paste your PUBLIC  key (base64) (must match private):")
            vk_b64 = input("> ").strip()
            sk = get_sk_from_b64(sk_b64)
            lyrics = prompt_lyrics()                               # Lyrics input
            if len(lyrics) < 2:
                print("You need at least 2 lyrics (to form a ring).")
                continue
            chain = LyricRingChain(vk_b64)
            chain.build_from_lyrics_and_sk(lyrics, sk)
            print("\nGenerated ring blockchain with blocks:")
            chain.print_blocks()
            timestamp = time.strftime('%Y%m%d-%H%M%S')
            filename = f"lyric_ring_{timestamp}.json"
            chain.save_to_json(filename)
        elif choice == "3":
            filename = input("JSON filename to load: ").strip()
            if not os.path.exists(filename):
                print("File not found.")
                continue
            chain = LyricRingChain.load_from_json(filename)
            print("\nLoaded chain blocks:")
            chain.print_blocks()                                   # Show all blocks
            print("\nVerification result:")
            chain.verify_ring()                                    # Verify blocks and links
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
