#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###############################################################################
#  Lyric-Ring 区块链工具（加强注释 & 行数组 JSON 版）
#
#  2026-02-02
#  ---------------------------------------------------------------------------
#  功能：
#    1. 生成/导入 secp256k1 私钥，输出三种格式。
#    2. 创建环形区块链（歌词可含多行缩进，保存为行数组，JSON 无 \n 转义）。
#    3. 保存 / 载入 JSON。
#    4. 输入公钥后逐块验签并定位任何错误。
###############################################################################

import base64
import hashlib
import json
import os
import time
from typing import List

import ecdsa

# ─────────────────────────────────────────────────────────────────────────────
# 编码 / 解析辅助函数
# ─────────────────────────────────────────────────────────────────────────────
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def sk_to_hex(sk): return sk.to_string().hex()
def sk_to_dec(sk): return str(int.from_bytes(sk.to_string(), "big"))
def sk_to_b64(sk): return b64e(sk.to_string())

def vk_to_hex(vk): return vk.to_string().hex()
def vk_to_dec(vk): return str(int.from_bytes(vk.to_string(), "big"))
def vk_to_b64(vk): return b64e(vk.to_string())

def parse_private(text: str):
    t = text.strip()
    # HEX
    try:
        b = bytes.fromhex(t)
        if len(b) == 32:
            return ecdsa.SigningKey.from_string(b, curve=ecdsa.SECP256k1)
    except Exception:
        pass
    # DEC
    try:
        b = int(t).to_bytes(32, 'big')
        return ecdsa.SigningKey.from_string(b, curve=ecdsa.SECP256k1)
    except Exception:
        pass
    # B64
    try:
        b = base64.b64decode(t.encode())
        if len(b) == 32:
            return ecdsa.SigningKey.from_string(b, curve=ecdsa.SECP256k1)
    except Exception:
        pass
    raise ValueError("私钥解析失败：需 64 位 HEX / 十进制 / base64")

def parse_public(text: str):
    t = text.strip()
    # B64
    try:
        b = base64.b64decode(t.encode())
        if len(b) == 64:
            return ecdsa.VerifyingKey.from_string(b, curve=ecdsa.SECP256k1)
    except Exception:
        pass
    # HEX
    try:
        b = bytes.fromhex(t)
        if len(b) == 64:
            return ecdsa.VerifyingKey.from_string(b, curve=ecdsa.SECP256k1)
    except Exception:
        pass
    # DEC
    try:
        b = int(t).to_bytes(64, 'big')
        return ecdsa.VerifyingKey.from_string(b, curve=ecdsa.SECP256k1)
    except Exception:
        pass
    raise ValueError("公钥解析失败")

# ─────────────────────────────────────────────────────────────────────────────
# 区块定义
# ─────────────────────────────────────────────────────────────────────────────
def calc_hash(lyric_text: str, pub_b64: str) -> str:
    """block_hash = SHA256(歌词全文 + 公钥)"""
    return hashlib.sha256((lyric_text + pub_b64).encode()).hexdigest()

class Block:
    """
    字段
      lyric_lines : list[str]   —  原始多行文本（保持缩进）
      public_key  : str(base64)
      prev_hash   : str(64 hex)
      block_hash  : str(64 hex)
      signature   : str(base64)
    """
    def __init__(self, lyric_lines: List[str], pub_b64: str):
        self.lyric_lines = lyric_lines
        self.public_key = pub_b64
        self.prev_hash = ""
        self.block_hash = calc_hash('\n'.join(lyric_lines), pub_b64)
        self.signature = ""

    # ── 签名
    def sign(self, sk):
        msg = ('\n'.join(self.lyric_lines)
               + self.block_hash
               + self.prev_hash
               + self.public_key)
        self.signature = b64e(sk.sign(msg.encode()))

    # ── 验签
    def verify(self, vk) -> bool:
        if self.public_key != vk_to_b64(vk):
            return False
        if self.block_hash != calc_hash('\n'.join(self.lyric_lines),
                                        self.public_key):
            return False
        msg = ('\n'.join(self.lyric_lines)
               + self.block_hash
               + self.prev_hash
               + self.public_key)
        try:
            return vk.verify(base64.b64decode(self.signature), msg.encode())
        except Exception:
            return False

    # ── 序列化
    def to_dict(self):
        return {
            "lyric_lines": self.lyric_lines,
            "prev_hash": self.prev_hash,
            "block_hash": self.block_hash,
            "public_key": self.public_key,
            "signature": self.signature
        }

    @staticmethod
    def from_dict(d):
        blk = Block(d["lyric_lines"], d["public_key"])
        blk.prev_hash = d["prev_hash"]
        blk.block_hash = d["block_hash"]
        blk.signature = d["signature"]
        return blk

# ─────────────────────────────────────────────────────────────────────────────
# 环形链
# ─────────────────────────────────────────────────────────────────────────────
class Ring:
    def __init__(self, pub_b64: str):
        self.pub_b64 = pub_b64
        self.blocks: List[Block] = []

    # ---------- 构建 ----------
    def build(self, lyrics_lines_list: List[List[str]], sk):
        """
        lyrics_lines_list : List[ List[str] ]   每个元素是一段文本的行数组
        """
        if len(lyrics_lines_list) < 2:
            raise ValueError("需要至少 2 个区块形成环")

        # 1. 创建区块对象
        self.blocks = []
        for lines in lyrics_lines_list:
            self.blocks.append(Block(lines, self.pub_b64))

        # 2. 设置 prev_hash（环形）
        n = len(self.blocks)
        self.blocks[0].prev_hash = self.blocks[n - 1].block_hash
        for i in range(1, n):
            self.blocks[i].prev_hash = self.blocks[i - 1].block_hash

        # 3. 逐块签名
        for blk in self.blocks:
            blk.sign(sk)

    # ---------- 保存 ----------
    def save(self, fname):
        data = {
            "public_key": self.pub_b64,
            "block_list": []
        }
        for blk in self.blocks:
            data["block_list"].append(blk.to_dict())
        with open(fname, 'w', encoding='utf-8') as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)

    # ---------- 载入 ----------
    @staticmethod
    def load(fname):
        with open(fname, 'r', encoding='utf-8') as fp:
            data = json.load(fp)
        ring = Ring(data["public_key"])
        for d in data["block_list"]:
            ring.blocks.append(Block.from_dict(d))
        return ring

    # ---------- 校验 ----------
    def verify(self, vk):
        ok = True
        if self.pub_b64 != vk_to_b64(vk):
            print("❌ 公钥不匹配")
            return False

        n = len(self.blocks)
        for i in range(n):
            blk = self.blocks[i]
            # 验签 & 自 hash
            if not blk.verify(vk):
                print(f"❌ Block {i} : 签名或 block_hash 错误")
                ok = False
            # prev_hash
            prev_idx = (i - 1) % n
            if blk.prev_hash != self.blocks[prev_idx].block_hash:
                print(f"❌ Block {i} : prev_hash ≠ Block {prev_idx}.block_hash")
                ok = False
        if ok:
            print("✅ Chain verification succeeded.")
        return ok

    # ---------- 打印 ----------
    def pretty(self):
        print("\n=== Chain Public Key (B64) ===\n" + self.pub_b64)
        for i, b in enumerate(self.blocks):
            print(f"\nBlock {i}:")
            print("  lyric_lines:")
            for ln in b.lyric_lines:
                print("     ", ln)
            print("  prev_hash :", b.prev_hash)
            print("  block_hash:", b.block_hash)
            print("  signature :", b.signature)

# ─────────────────────────────────────────────────────────────────────────────
# 默认内容（多行/缩进/医疗知识/代码片段示例）
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_RAW = [
    """Shadows slow dance on the pavement tonight,""",
    """Neon memories flicker under broken streetlights,""",
    """Old hopes waiting for the corners of dawn,""",
    """Every heartbeat writing a line in my song.""",
    """# 随机代码片段
def hello():
    print("hello world")
""",
    """医学常识：
  • 正常成年人收缩压 90–140 mmHg
  • 静息心率 60–100 次/分"""
]

# 转成行数组
DEFAULT_LYRICS = [txt.splitlines() for txt in DEFAULT_RAW]

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def menu():
    print("\n====== Lyric-Ring CLI ======")
    print("1. 生成新密钥对")
    print("2. 创建环形区块链并保存")
    print("3. 载入 JSON 并校验")
    print("4. 退出")
    print("============================")

def new_key():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    print("\n=== NEW KEY PAIR ===")
    print("Private HEX :", sk_to_hex(sk))
    print("Private DEC :", sk_to_dec(sk))
    print("Private B64 :", sk_to_b64(sk))
    print("--------------------")
    print("Public  HEX :", vk_to_hex(vk))
    print("Public  DEC :", vk_to_dec(vk))
    print("Public  B64 :", vk_to_b64(vk))
    print("====================")
    return sk, vk

def input_multiline() -> List[List[str]]:
    print("请输入每个区块文本（空行结束一个区块，连续两空行结束全部）：")
    blocks: List[List[str]] = []
    cur: List[str] = []
    empty_count = 0
    while True:
        ln = input()
        if ln == "":
            empty_count += 1
            if empty_count == 2:
                break
            if cur:
                blocks.append(cur)
                cur = []
            continue
        empty_count = 0
        cur.append(ln)
    if cur:
        blocks.append(cur)
    return blocks

def create_chain():
    key_in = input("私钥 HEX/DEC/B64 (空 = 自动生成): ").strip()
    if key_in == "":
        sk, vk = new_key()
    else:
        try:
            sk = parse_private(key_in)
            vk = sk.verifying_key
        except ValueError as e:
            print("解析失败:", e)
            return
    # 选择歌词
    use_def = input("使用默认示例内容? (y/n): ").lower()
    if use_def == 'y':
        lyrics = DEFAULT_LYRICS.copy()
    else:
        lyrics = input_multiline()
    ring = Ring(vk_to_b64(vk))
    try:
        ring.build(lyrics, sk)
    except Exception as e:
        print("构建失败:", e)
        return
    ring.pretty()
    fname = f"lyric_ring_{time.strftime('%Y%m%d-%H%M%S')}.json"
    ring.save(fname)
    print("已保存到", fname)

def verify_chain():
    fname = input("JSON 文件名: ").strip()
    if not os.path.exists(fname):
        print("文件不存在")
        return
    pub_in = input("请输入公钥 (HEX/DEC/B64): ").strip()
    try:
        vk = parse_public(pub_in)
    except ValueError as e:
        print("公钥解析失败:", e)
        return
    ring = Ring.load(fname)
    ring.pretty()
    print("\n开始校验 ...")
    ring.verify(vk)

def main():
    while True:
        menu()
        ch = input("选择: ").strip()
        if ch == "1":
            new_key()
        elif ch == "2":
            create_chain()
        elif ch == "3":
            verify_chain()
        elif ch == "4":
            print("Bye.")
            break
        else:
            print("无效选择")

if __name__ == "__main__":
    main()
