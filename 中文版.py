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
        """从数据库获取所有区块（升序）"""
        cur = self.conn.cursor()
        cur.execute('SELECT data, prev_hash, hash, sign, pubkey FROM blocks ORDER BY id ASC')
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
========== 个人区块链记录系统（基于SQLite3） ==========
1. 创建新钱包（生成私钥、公钥）
2. 导入私钥
3. 显示当前公钥
4. 添加记录（多行，输入END结束）
5. 显示所有区块链记录
6. 验证区块链完整性
7. 退出
8. 查询指定公钥签名的区块
====================================================
""")
def create_block(data, prev_hash, wallet):
    """ 创建新区块，会自动计算哈希并签名 """
    hasher = hashlib.sha256()
    hasher.update((str(data) + str(prev_hash)).encode())
    block_hash = hasher.hexdigest()
    sign = wallet.sign(block_hash.encode())
    pubkey = wallet.get_public_key()
    return Block(data, prev_hash, block_hash, sign, pubkey)

def check_chain(blocks):
    """ 验证整条链的签名、哈希和连接关系 """
    if not blocks:
        print("区块链为空。")
        return False
    for idx in range(len(blocks)):
        block = blocks[idx]
        # 签名验证
        if not block.is_signature_valid():
            print("签名验证失败，出错区块号 {}".format(idx))
            return False
        # 链接关系验证
        if idx > 0:
            if block.prev_hash != blocks[idx - 1].hash:
                print("区块链链接断裂，出错区块号 {}".format(idx))
                return False
        # 哈希计算验证
        if block.hash != block.calc_hash():
            print("区块哈希不匹配，出错区块号 {}".format(idx))
            return False
    return True
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
            blocks = db.get_blocks()
            if len(blocks) > 0:
                prev_hash = blocks[-1].hash
            else:
                prev_hash = '0' * 64
            new_block = create_block(content, prev_hash, wallet)
            db.add_block(new_block)
            print("记录已添加区块链并存储到SQLite3数据库。")
        elif cmd == "5":
            blocks = db.get_blocks()
            print(f"总记录数: {len(blocks)}")
            for i in range(len(blocks)):
                blocks[i].display(i)
        elif cmd == "6":
            blocks = db.get_blocks()
            if check_chain(blocks):
                print("区块链完整性验证通过：无篡改、无断链、所有签名均有效。")
        elif cmd == "7":
            print("已退出。")
            break
        elif cmd == "8":
            pubkey = input("请输入要查询的公钥（hex）: ").strip()
            blocks = db.get_blocks()
            if not check_chain(blocks):
                print("链校验不通过，终止查询。")
                continue
            found = False
            for idx in range(len(blocks)):
                block = blocks[idx]
                if block.pubkey == pubkey:
                    print(f"★此公钥({pubkey})签名的区块:")
                    block.display(idx)
                    found = True
            if not found:
                print("未找到该公钥签名的区块。")
        else:
            print("输入无效，请重试。")
if __name__ == '__main__':
    main()
