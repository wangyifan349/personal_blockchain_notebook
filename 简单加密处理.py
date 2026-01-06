"""
这段代码实现了一个基于PyQt5图形界面和ChaCha20-Poly1305算法的批量文件加解密工具。用户只需选择目标文件夹并输入密码，通过界面按钮切换“加密”或“解密”模式，即可对所在目录下所有文件进行批量处理。所有操作在单独线程中完成，确保界面流畅不卡顿。加/解密过程会覆盖源文件但不会更改文件名和修改时间，每次操作仅针对选中文件夹（不递归子目录）。整个界面简洁直观，无多余输出栏，仅需几个步骤就可完成任务，非常适用于日常的小批量文件安全处理。
"""
import sys
import os
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QLineEdit,
    QMessageBox, QRadioButton, QButtonGroup)
from PyQt5.QtCore import QThread
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# 生成32字节密钥（SHA256，前32字节）
def derive_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()[:32]

# 覆盖加密文件内容
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plain_data = file.read()
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain_data)
    with open(file_path, 'wb') as file:
        file.write(nonce + tag + ciphertext)

# 覆盖解密文件内容
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    if len(file_data) < 28:
        return False
    nonce = file_data[:12]
    tag = file_data[12:28]
    ciphertext = file_data[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        plain_data = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        return False
    with open(file_path, 'wb') as file:
        file.write(plain_data)
    return True

# 多线程批量任务，防止界面卡顿
class BatchCryptoWorker(QThread):
    def __init__(self, directory_path, key, encrypt_mode, parent=None):
        super().__init__(parent)
        self.directory_path = directory_path
        self.key = key
        self.encrypt_mode = encrypt_mode

    def run(self):
        for file_name in os.listdir(self.directory_path):
            file_path = os.path.join(self.directory_path, file_name)
            if os.path.isfile(file_path):
                try:
                    original_mtime = os.path.getmtime(file_path)
                    if self.encrypt_mode:
                        encrypt_file(file_path, self.key)
                    else:
                        decrypt_file(file_path, self.key)
                    # 保持文件修改时间不变
                    os.utime(file_path, (original_mtime, original_mtime))
                except Exception:
                    continue

def main():
    app = QApplication(sys.argv)
    window = QWidget()
    window.setWindowTitle("ChaCha20-Poly1305 Batch Crypto Tool")
    window.setFixedSize(450, 150)
    main_layout = QVBoxLayout()

    # 路径选择
    dir_layout = QHBoxLayout()
    label_directory = QLabel("Directory:")
    edit_directory = QLineEdit()
    edit_directory.setReadOnly(True)
    button_select_directory = QPushButton("Browse")
    dir_layout.addWidget(label_directory)
    dir_layout.addWidget(edit_directory)
    dir_layout.addWidget(button_select_directory)
    main_layout.addLayout(dir_layout)

    # 密码输入
    pwd_layout = QHBoxLayout()
    label_password = QLabel("Password:")
    edit_password = QLineEdit()
    edit_password.setEchoMode(QLineEdit.Password)
    pwd_layout.addWidget(label_password)
    pwd_layout.addWidget(edit_password)
    main_layout.addLayout(pwd_layout)

    # 模式选择（加密/解密）
    mode_layout = QHBoxLayout()
    radio_encrypt = QRadioButton("Encrypt")
    radio_encrypt.setChecked(True)
    radio_decrypt = QRadioButton("Decrypt")
    button_group_mode = QButtonGroup(window)
    button_group_mode.addButton(radio_encrypt)
    button_group_mode.addButton(radio_decrypt)
    mode_layout.addWidget(radio_encrypt)
    mode_layout.addWidget(radio_decrypt)
    mode_layout.addStretch()
    main_layout.addLayout(mode_layout)

    # 开始按钮
    start_layout = QHBoxLayout()
    button_start = QPushButton("Start")
    start_layout.addStretch()
    start_layout.addWidget(button_start)
    start_layout.addStretch()
    main_layout.addLayout(start_layout)

    window.setLayout(main_layout)

    state = {'worker': None}

    # 选择文件夹
    def select_directory():
        directory_path = QFileDialog.getExistingDirectory(window, "Select Directory")
        if directory_path:
            edit_directory.setText(directory_path)

    # 任务结束恢复按钮
    def on_worker_finished():
        button_start.setEnabled(True)
        button_select_directory.setEnabled(True)
        state['worker'] = None

    # 启动加/解密任务
    def start_crypto_task():
        directory_path = edit_directory.text().strip()
        password = edit_password.text().strip()
        if not directory_path or not os.path.isdir(directory_path):
            QMessageBox.warning(window, "Error", "Please select a valid directory.")
            return
        if not password:
            QMessageBox.warning(window, "Error", "Please enter a password.")
            return
        key = derive_key(password)
        encrypt_mode = radio_encrypt.isChecked()
        button_start.setEnabled(False)
        button_select_directory.setEnabled(False)
        worker = BatchCryptoWorker(directory_path, key, encrypt_mode)
        worker.finished.connect(on_worker_finished)
        worker.start()
        state['worker'] = worker

    button_select_directory.clicked.connect(select_directory)
    button_start.clicked.connect(start_crypto_task)

    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
