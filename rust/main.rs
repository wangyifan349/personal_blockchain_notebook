### `Cargo.toml

````toml
[package]
name = "blockchain_record"
version = "0.1.0"
edition = "2021"

[dependencies]
rusqlite = "0.31"
secp256k1 = { version = "0.29", features = ["rand"] }
sha2 = "0.10"
hex = "0.4"
rand = "0.8"
```

---

## `src/main.rs`

use rusqlite::{params, Connection};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdsa::Signature};
use sha2::{Digest, Sha256};
use rand::rngs::OsRng;
use std::io::{self, Write};
use hex::{encode, decode};

// -------- 钱包结构体：负责公私钥生成/签名/验签 ----------
struct Wallet {
    sk: SecretKey,
    pk: PublicKey,
}
impl Wallet {
    // 创建新钱包（生成新私钥和公钥）
    fn new() -> Self {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        Self { sk, pk }
    }
    // 通过十六进制私钥导入钱包
    fn from_hex(priv_hex: &str) -> Option<Self> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&decode(priv_hex).ok()?).ok()?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        Some(Self { sk, pk })
    }
    // 返回私钥（十六进制）
    fn private_key_hex(&self) -> String {
        encode(self.sk.secret_bytes())
    }
    // 返回公钥（十六进制，未压缩）
    fn public_key_hex(&self) -> String {
        encode(self.pk.serialize_uncompressed())
    }
    // 使用当前私钥对内容进行签名，结果为十六进制DER编码
    fn sign(&self, content: &[u8]) -> String {
        let secp = Secp256k1::signing_only();
        let msg = Message::from_slice(content).unwrap();
        let sig = secp.sign_ecdsa(&msg, &self.sk);
        encode(sig.serialize_der())
    }
    // 校验签名（公钥/签名/原文）是否有效
    fn verify(pub_hex: &str, sig_hex: &str, content: &[u8]) -> bool {
        let secp = Secp256k1::verification_only();
        let pk_bytes = decode(pub_hex).unwrap_or_default();
        let pk = PublicKey::from_slice(&pk_bytes).ok()?;
        let sig_bytes = decode(sig_hex).unwrap_or_default();
        let sig = Signature::from_der(&sig_bytes).ok()?;
        let msg = Message::from_slice(content).ok()?;
        secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
    }
}

// -------- 区块结构体，每条数据链上都有 --------
#[derive(Debug, Clone)]
struct Block {
    data: String,       // 区块内容（支持多行）
    prev_hash: String,  // 前一个区块的哈希（链式结构关键）
    hash: String,       // 当前区块的SHA256哈希
    sign: String,       // 内容签名，十六进制DER
    pubkey: String,     // 当前钱包公钥（签发人身份标识）
}

impl Block {
    // 创建新区块，包括自动哈希、签名
    fn new(data: String, prev_hash: String, wallet: &Wallet) -> Self {
        // 哈希算法与Python一致
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", data, prev_hash).as_bytes());
        let hash = encode(hasher.finalize());
        let sign = wallet.sign(hash.as_bytes());
        let pubkey = wallet.public_key_hex();
        Block {
            data,
            prev_hash,
            hash,
            sign,
            pubkey,
        }
    }
    // 校验签名有效性
    fn verify_signature(&self) -> bool {
        Wallet::verify(
            &self.pubkey,
            &self.sign,
            self.hash.as_bytes(),
        )
    }
    // 重新计算哈希，用于结构体内容校检
    fn calc_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", self.data, self.prev_hash));
        encode(hasher.finalize())
    }
    // 友好打印（带索引信息）
    fn display(&self, index: usize) {
        println!("-------------------- Block {} ---------------------", index);
        println!("Data:\n{}", self.data);
        println!("Prev Hash: {}", self.prev_hash);
        println!("Hash     : {}", self.hash);
        println!("Signature: {}", self.sign);
        println!("Pub Key  : {}", self.pubkey);
        println!("Signature valid? {}", self.verify_signature());
        println!("---------------------------------------------------");
    }
}

// -------- 链式数据库，SQLite管理区块存储 ---------
struct ChainDB {
    conn: Connection,    // rusqlite数据库连接
}
impl ChainDB {
    // 打开数据库并自动建表
    fn new(path: &str) -> Self {
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT,
                prev_hash TEXT,
                hash TEXT,
                sign TEXT,
                pubkey TEXT
             )", [],
        ).unwrap();
        Self { conn }
    }
    // 新增区块到数据库
    fn add_block(&self, block: &Block) {
        self.conn.execute(
            "INSERT INTO blocks (data, prev_hash, hash, sign, pubkey) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                block.data,
                block.prev_hash,
                block.hash,
                block.sign,
                block.pubkey
            ],
        ).unwrap();
    }
    // 按顺序获取所有区块
    fn get_blocks(&self) -> Vec<Block> {
        let mut stmt = self.conn.prepare(
            "SELECT data, prev_hash, hash, sign, pubkey FROM blocks ORDER BY id ASC"
        ).unwrap();
        let res = stmt
            .query_map([], |row| {
                Ok(Block {
                    data: row.get(0)?,
                    prev_hash: row.get(1)?,
                    hash: row.get(2)?,
                    sign: row.get(3)?,
                    pubkey: row.get(4)?,
                })
            }).unwrap();
        res.filter_map(|r| r.ok()).collect()
    }
}

// ---------- 最长公共子序列，文本模糊检索 ---------
fn longest_common_subsequence(a: &str, b: &str) -> usize {
    let m = a.len();
    let n = b.len();
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut dp = vec![vec![0; n + 1]; m + 1];
    for i in 0..m {
        for j in 0..n {
            if a_bytes[i] == b_bytes[j] {
                dp[i+1][j+1] = dp[i][j] + 1;
            } else {
                dp[i+1][j+1] = dp[i][j+1].max(dp[i+1][j]);
            }
        }
    }
    dp[m][n]
}

// --------- 校验整条区块链合法性与安全性 -----------
fn check_chain(blocks: &Vec<Block>) -> bool {
    if blocks.is_empty() {
        println!("Chain is empty.");
        return true;
    }
    for (idx, block) in blocks.iter().enumerate() {
        // 签名校验
        if !block.verify_signature() {
            println!("# Signature validation failed at block {}", idx);
            return false;
        }
        // 区块引用前一块的哈希是否断裂
        if idx > 0 && block.prev_hash != blocks[idx-1].hash {
            println!("# Chain linkage broken at block {}", idx);
            return false;
        }
        // 哈希内容与实际重新计算是否一致
        if block.hash != block.calc_hash() {
            println!("# Hash mismatch at block {}", idx);
            return false;
        }
    }
    true
}

// =================== 主菜单循环 =====================
fn main() {
    let db_path = "blockchain.db";
    let db = ChainDB::new(db_path);
    let mut wallet: Option<Wallet> = None;

    loop {
        println!("\n================ Blockchain System (Rust版) ================");
        println!("1. 创建新钱包 (私钥/公钥生成)");
        println!("2. 导入私钥");
        println!("3. 查看当前钱包公钥");
        println!("4. 新增区块记录（多行输入，以END结尾）");
        println!("5. 查看所有区块");
        println!("6. 校验链完整性");
        println!("7. 退出");
        println!("8. 查询某公钥签发的所有区块");
        println!("9. LCS模糊全文检索记录");
        println!("============================================================");

        print!("请选择功能（1-9）: ");
        io::stdout().flush().unwrap();
        let mut cmd = String::new();
        io::stdin().read_line(&mut cmd).unwrap();
        let cmd = cmd.trim();

        match cmd {
            "1" => {
                wallet = Some(Wallet::new());
                let w = wallet.as_ref().unwrap();
                println!("# 新钱包已生成");
                println!("私钥(hex): {}", w.private_key_hex());
                println!("请妥善备份私钥！");
                println!("公钥(hex): {}", w.public_key_hex());
            }
            "2" => {
                print!("请输入私钥(hex): ");
                io::stdout().flush().unwrap();
                let mut priv_hex = String::new();
                io::stdin().read_line(&mut priv_hex).unwrap();
                wallet = Wallet::from_hex(priv_hex.trim());
                if wallet.is_some() {
                    println!("# 私钥导入成功，公钥: {}", wallet.as_ref().unwrap().public_key_hex());
                } else {
                    println!("# 私钥导入失败，请检查格式。");
                }
            }
            "3" => {
                if let Some(w) = &wallet {
                    println!("当前钱包公钥(hex): {}", w.public_key_hex());
                } else {
                    println!("# 请先创建或导入钱包。");
                }
            }
            "4" => {
                if wallet.is_none() {
                    println!("# 请先创建或导入钱包。");
                    continue;
                }
                println!("请输入记录正文，支持多行（END结尾）：");
                let mut lines = Vec::new();
                loop {
                    let mut line = String::new();
                    io::stdin().read_line(&mut line).unwrap();
                    let line = line.trim_end();
                    if line == "END" { break; }
                    lines.push(line.to_string());
                }
                if lines.is_empty() {
                    println!("# 记录不能为空。");
                    continue;
                }
                let content = lines.join("\n");
                let blocks = db.get_blocks();
                let prev_hash = if let Some(last) = blocks.last() {
                    last.hash.clone()
                } else {
                    "0".repeat(64)
                };
                let new_block = Block::new(content, prev_hash, wallet.as_ref().unwrap());
                db.add_block(&new_block);
                println!("# 区块添加完毕！（已写入数据库，带数字签名）");
            }
            "5" => {
                let blocks = db.get_blocks();
                println!("区块总数: {}", blocks.len());
                for (i, b) in blocks.iter().enumerate() {
                    b.display(i);
                }
            }
            "6" => {
                let blocks = db.get_blocks();
                if check_chain(&blocks) {
                    println!("# 区块链校验通过：未发现篡改、删改、签名无效问题。");
                }
            }
            "7" => {
                println!("退出程序。");
                break;
            }
            "8" => {
                print!("请输入要查询的公钥(hex): ");
                io::stdout().flush().unwrap();
                let mut pub_hex = String::new();
                io::stdin().read_line(&mut pub_hex).unwrap();
                let pub_hex = pub_hex.trim();
                let blocks = db.get_blocks();
                if !check_chain(&blocks) {
                    println!("# 链校验失败，查询中止。");
                    continue;
                }
                let mut found = false;
                for (i, b) in blocks.iter().enumerate() {
                    if b.pubkey == pub_hex {
                        b.display(i);
                        found = true;
                    }
                }
                if !found {
                    println!("# 未发现该公钥签发的区块。");
                }
            }
            "9" => {
                print!("请输入LCS模糊匹配的关键字: ");
                io::stdout().flush().unwrap();
                let mut keyword = String::new();
                io::stdin().read_line(&mut keyword).unwrap();
                let keyword = keyword.trim();
                let blocks = db.get_blocks();
                if !check_chain(&blocks) {
                    println!("# 链校验失败，查询中止。");
                    continue;
                }
                let mut scored: Vec<(usize, usize, &Block)> = vec![];
                for (i, b) in blocks.iter().enumerate() {
                    let lcs = longest_common_subsequence(&b.data, keyword);
                    if lcs > 0 {
                        scored.push((lcs, i, b));
                    }
                }
                scored.sort_by(|a, b| b.0.cmp(&a.0));
                if scored.is_empty() {
                    println!("# 未找到任何LCS匹配的区块。");
                } else {
                    println!("# LCS相关区块（按匹配长度降序）: ");
                    for (score, i, b) in scored {
                        println!("==> [LCS长度: {}]", score);
                        b.display(i);
                    }
                }
            }
            _ => println!("无效输入，请重试。"),
        }
    }
}
