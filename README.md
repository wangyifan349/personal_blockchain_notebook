# Personal Blockchain Record System
## Overview

This project is a command-line personal blockchain record system implemented in Python, persisting data in an SQLite database. Every record you write forms a new block, linked securely to the previous one, cryptographically signed with your private key, and visible for verification at any time. The system is ideal for keeping authentic, time-stamped logs, contracts, agreements, or research notes with tamper-evident and traceable audit trails—all locally, without the need for servers or any internet services.

## Core Principles and Chain Structure

- **Linked Block Structure:** Each record, or "block," captures the written content (`data`), the hash of the previous block (`prev_hash`), its own hash (`hash`), the user's public key (`pubkey`), and a digital signature (`sign`). The hash is computed over the block’s content and the previous hash, forming a one-way chain. This design ensures that any modification—no matter how small—to a previous block or its order will break the chain and be instantly detectable.
- **Cryptographic Security:** Each block’s hash is signed using ECDSA (Elliptic Curve Digital Signature Algorithm, SECP256k1 curve) with your private key. This means every entry is uniquely yours, and only you (with your private key) can author new records attributed to yourself. Signatures are always verified on reading or searching.
- **Permanent and Auditable History:** New blocks are always appended; the chain’s design makes rewriting or deleting past entries immediately detectable. Chain and signature verification can be run at any time to audit the integrity and provenance of every record.
- **Public Key Attribution & Multi-User Potential:** Different public keys can issue blocks in the same database, and the system can search for all blocks signed by a particular public key, making it suitable (with some scripting) for team or group usage.

## Functionality

- **Wallet Management:** Generate a new wallet (ECDSA keypair) or import an existing private key for continuous usage.
- **Add Records:** Enter multi-line notes, agreements, logs, or any text, sealed in a new blockchain block.
- **Blockchain Integrity Verification:** At any stage, validate the entire chain’s linkage and all signatures.
- **View & Query:** List all records, lookup all records by the public key that signed them, or perform advanced searches using fuzzy matching based on the longest common subsequence (LCS) with your keyword.
- **Automatic Persistence:** All blocks are safely stored in SQLite3—no dependence on flat files or risky transient data.

## Usage Overview

1. Install dependencies using `pip install ecdsa`.
2. Run the script with Python 3.
3. Follow the menu:  
   - Generate/import wallet,  
   - Add new records,  
   - View all history,  
   - Search or verify the chain.  
4. Backup your private key carefully; it is needed for signing future entries.
5. The SHA256 hash of the database is displayed at every startup, supporting offline archival and verification.

## License

This project is released under the MIT License (see the code for full terms). You are free to use, modify, and distribute this code.

## **Important Privacy Notice**

**The entire database is stored in a fully readable, transparent form. All record data, public keys, and digital signatures are visible to anyone with access to the SQLite database file. There is NO encryption or access control built in. If you require data privacy, please use strong encryption externally or take appropriate operational security measures. Do not store confidential, personal, or sensitive data unless you understand the full implications.**

