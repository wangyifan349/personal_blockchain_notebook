# ===================================
# 版本: v2.1
#
# 功能亮点：
# - 多用户分链，每个公钥形成自己独立的区块链（链内prev_hash只链接自己上一块）
# - 全体链保存在sqlite3数据库，公私钥sha256签名保护
# - 菜单交互式操作：私钥管理、写入区块、全链展示
# - 【升级】校验功能可详细逐一输出每个用户链的校验结果
#    - 每个人链最后区块哈希都显示
#    - 校验失败时具体指出问题（区块序号、错误细节摘要）
#    - 汇总每个用户是否校验通过
# - 去除了LCS模糊搜索功能，只做严谨链验证
#
# 主要修改点：
# 1.  check_all_user_chains函数升级，逐个用户检查，逐项print结果并输出校验通过/失败名单及最后块hash
# 2.  校验失败时会明确说明哪项失败（签名、断链、哈希不一致），断点细节可追溯
# 3.  其它结构、菜单与分链区块写入逻辑与先前一致
# ===================================

import hashlib
import ecdsa
import sqlite3
import os

DB_PATH = "blockchain.db"

def print_db_sha256():
    """ 程序启动时打印数据库文件的SHA256哈希 """
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "rb") as f:
            db_bytes = f.read()
        sha = hashlib.sha256(db_bytes).hexdigest()
        print(f"当前数据库SHA256: {sha}")
    else:
        print(f"数据库文件 {DB_PATH} 不存在，无法获取SHA256。")

class Wallet:
    """ 钱包类，用于管理私钥、公钥和签名 """
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
    """ 区块类，代表单个区块链记录 """
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
        hasher.update((str(self.data) + str(self.prev_hash)).encode())
        return hasher.hexdigest()
    def display(self, index):
        print(f"区块 {index}:")
        print(f" 内容 :\n{self.data}")
        print(f" 前一区块哈希 : {self.prev_hash}")
        print(f" 当前哈希 : {self.hash}")
        print(f" 签名 : {self.sign}")
        print(f" 公钥 : {self.pubkey}")
        print(f" 签名校验 : {self.is_signature_valid()}")
        print('-'*60)

class ChainDB:
    """ 区块链数据库（基于SQLite） """
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
        """获取所有区块（升序，包括所有公钥）"""
        cur = self.conn.cursor()
        cur.execute('SELECT data, prev_hash, hash, sign, pubkey FROM blocks ORDER BY id ASC')
        rows = cur.fetchall()
        blocks = []
        for row in rows:
            block = Block(row[0], row[1], row[2], row[3], row[4])
            blocks.append(block)
        return blocks
    def get_blocks_by_pubkey(self, pubkey):
        """返回指定公钥按插入顺序排列的所有区块"""
        cur = self.conn.cursor()
        cur.execute('SELECT data, prev_hash, hash, sign, pubkey FROM blocks WHERE pubkey=? ORDER BY id ASC', (pubkey,))
        rows = cur.fetchall()
        blocks = []
        for row in rows:
            block = Block(row[0], row[1], row[2], row[3], row[4])
            blocks.append(block)
        return blocks
    def add_block(self, block):
        """添加新区块到数据库"""
        cur = self.conn.cursor()
        cur.execute('INSERT INTO blocks (data, prev_hash, hash, sign, pubkey) VALUES (?, ?, ?, ?, ?)',
                    (block.data, block.prev_hash, block.hash, block.sign, block.pubkey))
        self.conn.commit()

def menu():
    """ 主菜单界面 """
    print("""
========== 个人分链区块链记录系统（基于SQLite3） ==========
1. 创建新钱包（生成私钥、公钥）
2. 导入私钥
3. 显示当前公钥
4. 添加记录（多行，输入END结束，仅链接自己历史）
5. 显示所有区块链记录（全体用户）
6. 校验所有用户链完整性
7. 退出
8. 查询指定公钥签名的区块
==========================================================
""")

def create_block(data, prev_hash, wallet):
    """ 创建新区块，会自动计算哈希并签名 """
    hasher = hashlib.sha256()
    hasher.update((str(data) + str(prev_hash)).encode())
    block_hash = hasher.hexdigest()
    sign = wallet.sign(block_hash.encode())
    pubkey = wallet.get_public_key()
    return Block(data, prev_hash, block_hash, sign, pubkey)

def check_all_user_chains(db):
    """
    对所有公钥的链逐个校验。每个人：
    - print链的最后hash
    - 校验到哪里失败给具体提示
    - 汇总哪些用户通过、哪些没通过
    - 异常指明断点和失败原因
    """
    cur = db.conn.cursor()
    cur.execute('SELECT DISTINCT pubkey FROM blocks')
    pubkeys = [row[0] for row in cur.fetchall()]
    if not pubkeys:
        print("当前无任何用户链。")
        return True

    passed_users = []
    failed_users = []
    last_hash_dict = {}
    for pubkey in pubkeys:
        blocks = db.get_blocks_by_pubkey(pubkey)
        if not blocks:
            print(f"公钥 {pubkey[:16]}... 未找到任何区块，跳过。")
            continue
        print(f"\n校验公钥 {pubkey[:16]}... 的链（共{len(blocks)}个区块）:")
        fail_info = None
        for idx, block in enumerate(blocks):
            if not block.is_signature_valid():
                fail_info = f" ✗ 区块{idx}: 签名验证失败\n    哈希: {block.hash[:20]}...\n    内容摘要: {block.data[:50]}"
                break
            if idx > 0 and block.prev_hash != blocks[idx-1].hash:
                fail_info = f" ✗ 区块{idx}: 上一区块哈希链断裂\n    当前区块 prev_hash: {block.prev_hash[:20]}...\n    应为: {blocks[idx-1].hash[:20]}..."
                break
            if block.hash != block.calc_hash():
                fail_info = f" ✗ 区块{idx}: 哈希自校验失败（内容可能被改过）\n    期望哈希: {block.calc_hash()[:20]}...\n    实际哈希: {block.hash[:20]}..."
                break
        if not fail_info:
            print(f" ✓ 该公钥链完整。最后区块哈希：{blocks[-1].hash}")
            passed_users.append(pubkey)
            last_hash_dict[pubkey] = blocks[-1].hash
        else:
            print(fail_info)
            print(f" ✗ 公钥 {pubkey[:16]}... 的链校验失败！")
            failed_users.append(pubkey)
    print("\n======= 校验汇总 =======")
    print(f"校验通过用户（{len(passed_users)}个）：")
    for k in passed_users:
        print(f"  {k[:48]}...  最后块哈希: {last_hash_dict[k]}")
    print(f"校验失败用户（{len(failed_users)}个）：")
    for k in failed_users:
        print(f"  {k[:48]}...")
    if len(failed_users) == 0:
        print("\n所有用户链完整性验证通过：无篡改、无断链、所有签名均有效。")
        return True
    else:
        print("\n部分用户链验证发现异常！请根据上方提示排查。")
        return False

def main():
    print_db_sha256()  # 启动时显示数据库SHA256
    wallet = None
    db = ChainDB()
    while True:
        menu()
        try:
            cmd = input("请选择菜单功能（1-8）：").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n程序已退出。")
            break
        if cmd == "1":
            wallet = Wallet()
            print("新钱包已生成。")
            print("私钥（hex）:", wallet.get_private_key())
            print("请务必安全备份好你的私钥！")
            print("公钥（hex）:", wallet.get_public_key())
        elif cmd == "2":
            priv = input("请输入私钥（hex）: ").strip()
            try:
                wallet = Wallet(priv)
                print("私钥导入成功。公钥（hex）:", wallet.get_public_key())
            except Exception as e:
                print("私钥导入失败，请检查格式。", str(e))
        elif cmd == "3":
            if wallet:
                print("当前钱包公钥（hex）:", wallet.get_public_key())
            else:
                print("请先创建或导入钱包。")
        elif cmd == "4":
            if not wallet:
                print("请先创建或导入钱包。")
                continue
            print("请输入你的记录内容（支持多行，输入END结束）：")
            lines = []
            while True:
                try:
                    line = input()
                except (KeyboardInterrupt, EOFError):
                    print("输入被中断。")
                    lines = []
                    break
                if line.strip() == "END":
                    break
                lines.append(line)
            if not lines:
                print("未添加内容。")
                continue
            content = "\n".join(lines)
            user_blocks = db.get_blocks_by_pubkey(wallet.get_public_key())
            if len(user_blocks) > 0:
                prev_hash = user_blocks[-1].hash
            else:
                prev_hash = '0' * 64
            new_block = create_block(content, prev_hash, wallet)
            db.add_block(new_block)
            print("你的记录已以区块形式添加到你自己的链上并存储到数据库。")
        elif cmd == "5":
            blocks = db.get_blocks()
            print(f"总区块数: {len(blocks)}")
            for i in range(len(blocks)):
                blocks[i].display(i)
        elif cmd == "6":
            check_all_user_chains(db)
        elif cmd == "7":
            print("已退出。")
            break
        elif cmd == "8":
            pubkey = input("请输入要查询的公钥（hex）: ").strip()
            blocks = db.get_blocks_by_pubkey(pubkey)
            if not blocks:
                print("该公钥下无区块。")
            else:
                print(f'该公钥({pubkey})签名的区块如下：')
                for idx, block in enumerate(blocks):
                    block.display(idx)
        else:
            print("输入无效，请重试。")
if __name__ == '__main__':
    main()
