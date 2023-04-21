import sys

from des import DES

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (QWidget, QLabel, QLineEdit,
                               QTextEdit, QGridLayout, QApplication, QPushButton, QFileDialog)


class GUI(QWidget):

    def __init__(self):
        super().__init__()
        self.encrypting_file = False
        self.decrypting_file = False
        self.file_path = ''
        self.initUI()

    def initUI(self):
        text_key = QLabel('Key:')
        self.key_edit = QLineEdit()

        self.plain_text = QTextEdit()
        self.plain_text.setPlaceholderText('Plaintext...')
        self.cypher_text = QTextEdit()
        self.cypher_text.setPlaceholderText('Cyphertext...')

        self.encryption = QPushButton(">>")
        self.encryption.clicked.connect(self.encrypt_on_click)
        self.decryption = QPushButton("<<")
        self.decryption.clicked.connect(self.decrypt_on_click)

        remind_text1 = QLabel('Encryption: >> ; Decryption: <<')
        remind_text2 = QLabel('You can also upload a file to encrypt or decrypt.')

        self.plain_fileButton = QPushButton("Upload File", self)
        self.cypher_fileButton = QPushButton("Upload File", self)
        self.plain_fileButton.clicked.connect(self.upload_file_plain)
        self.cypher_fileButton.clicked.connect(self.upload_file_cypher)

        self.plain_write = QPushButton("save", self)
        self.cypher_write = QPushButton("save", self)
        self.plain_write.clicked.connect(self.write_plain_text)
        self.cypher_write.clicked.connect(self.write_cypher_text)

        self.clear_plain = QPushButton("clear", self)
        self.clear_cypher = QPushButton("clear", self)
        self.clear_plain.clicked.connect(self.clear_plain_text)
        self.clear_cypher.clicked.connect(self.clear_cypher_text)

        self.encrypt_file = QPushButton("Encrypt File", self)
        self.decrypt_file = QPushButton("Decrypt File", self)
        self.encrypt_file.clicked.connect(self.encrypt_file_on_click)
        self.decrypt_file.clicked.connect(self.decrypt_file_on_click)

        # key_layout
        key_layout = QGridLayout()
        key_layout.setSpacing(10)
        key_layout.addWidget(text_key, 0, 0)
        key_layout.addWidget(self.key_edit, 0, 1)

        # sub_grid
        sub_grid = QGridLayout()
        sub_grid.setSpacing(10)

        sub_grid.setColumnStretch(0, 3)
        sub_grid.setColumnStretch(1, 1)
        sub_grid.setColumnStretch(2, 3)
        sub_grid.setRowStretch(0, 1)
        sub_grid.setRowStretch(1, 1)
        sub_grid.setRowStretch(2, 1)
        sub_grid.setRowStretch(3, 1)

        sub_grid.addWidget(self.plain_text, 0, 0, 4, 1)
        sub_grid.addWidget(self.encryption, 1, 1)
        sub_grid.addWidget(self.decryption, 2, 1)
        sub_grid.addWidget(self.cypher_text, 0, 2, 4, 1)

        # load_file_grid
        load_file_grid = QGridLayout()
        load_file_grid.setSpacing(2)

        load_file_grid.setColumnStretch(0, 1)
        load_file_grid.setColumnStretch(1, 1)
        load_file_grid.setColumnStretch(2, 1)
        load_file_grid.setColumnStretch(3, 1)
        load_file_grid.setColumnStretch(4, 1)
        load_file_grid.setColumnStretch(5, 1)
        load_file_grid.setColumnStretch(6, 1)

        load_file_grid.addWidget(self.plain_fileButton, 0, 0)
        load_file_grid.addWidget(self.plain_write, 0, 1)
        load_file_grid.addWidget(self.clear_plain, 0, 2)
        load_file_grid.addWidget(self.cypher_fileButton, 0, 4)
        load_file_grid.addWidget(self.cypher_write, 0, 5)
        load_file_grid.addWidget(self.clear_cypher, 0, 6)

        # file encryption&decryption grid
        file_grid = QGridLayout()
        # file_grid.setSpacing(5)

        file_grid.addWidget(self.encrypt_file, 0, 0)
        file_grid.addWidget(self.decrypt_file, 0, 2)

        file_grid.setColumnStretch(0, 3)
        file_grid.setColumnStretch(1, 1)
        file_grid.setColumnStretch(2, 3)

        # main grid
        grid = QGridLayout()
        grid.setSpacing(25)

        grid.addLayout(key_layout, 0, 0)
        grid.addLayout(load_file_grid, 1, 0)
        grid.addLayout(sub_grid, 2, 0)
        grid.addLayout(file_grid, 3, 0)
        grid.addWidget(remind_text1, 4, 0)
        grid.addWidget(remind_text2, 5, 0)

        self.setLayout(grid)

        self.setGeometry(300, 300, 600, 500)
        self.setWindowTitle('DES Algorithm')
        self.show()

    @Slot()
    def encrypt_on_click(self):
        if self.encrypting_file:
            if self.file_path.strip() == '' or self.key_edit.text().strip() == '' or self.get_plain_text() != '':
                return
            else:
                with open(self.file_path, 'rb') as f:
                    file_binary_data = f.read()
                    file_binary_data += b'\x05' + self.file_path.split('/')[-1].split('.')[-1].encode()
                des = DES()
                des.encrypt(file_binary_data, self.key_edit.text())
                dir_path = QFileDialog.getExistingDirectory(self, 'Select a folder:', '', QFileDialog.ShowDirsOnly)
                if not dir_path:
                    return
                with open(dir_path + '/' + self.file_path.split('/')[-1].split('.')[0] + '.des', 'wb') as f:
                    f.write(des.cypher_binary.encode())
                del des
                self.encrypting_file = False
                self.file_path = ''
                self.set_cypher_text("File Encrypted Successfully!")
                self.encrypt_file.setText("Encrypt File")
        else:
            if self.get_plain_text().strip() == '' or self.key_edit.text().strip() == '':
                return
            else:
                des = DES()
                des.encrypt(self.get_plain_text(), self.key_edit.text())
                self.set_cypher_text(des.cypher_text)
                del des

    @Slot()
    def decrypt_on_click(self):
        if self.decrypting_file:
            if self.file_path.strip() == '' or self.key_edit.text().strip() == '' or self.get_cypher_text() != '':
                return
            else:
                with open(self.file_path, 'rb') as f:
                    file_binary_data = f.read()

                des = DES()
                des.decrypt(file_binary_data.decode(), self.key_edit.text(), base_64=False)
                dir_path = QFileDialog.getExistingDirectory(self, 'Select a folder:', '', QFileDialog.ShowDirsOnly)
                if not dir_path:
                    return
                try:
                    file_extension = des.plain_text.split('\x05')[-1]
                    with open(dir_path + '/' + self.file_path.split('/')[-1].split('.')[0] + '.' + file_extension,
                              'wb') as f:
                        f.write(des.plain_binary.split(b'\x05')[0])
                except FileNotFoundError:
                    with open(dir_path + '/' + self.file_path.split('/')[-1].split('.')[0], 'wb') as f:
                        f.write(des.plain_text.encode())
                del des
                self.decrypting_file = False
                self.file_path = ''
                self.set_plain_text("File Decrypted Successfully!")
                self.decrypt_file.setText("Decrypt File")
        else:
            if self.get_cypher_text().strip() == '' or self.key_edit.text().strip() == '':
                return
            else:
                des = DES()
                des.decrypt(self.get_cypher_text(), self.key_edit.text())
                self.set_plain_text(des.plain_text)
                del des

    @Slot()
    def write_plain_text(self):
        dir_path = QFileDialog.getExistingDirectory(self, 'Select a folder:', '', QFileDialog.ShowDirsOnly)
        if not dir_path:
            return
        with open(dir_path + '/' + 'plain.txt', 'w') as f:
            f.write(self.get_plain_text())
        self.set_plain_text("saved as plain.txt successfully!")

    @Slot()
    def write_cypher_text(self):
        dir_path = QFileDialog.getExistingDirectory(self, 'Select a folder:', '', QFileDialog.ShowDirsOnly)
        if not dir_path:
            return
        with open(dir_path + '/' + 'cypher.txt', 'w') as f:
            f.write(self.get_cypher_text())
        self.set_cypher_text("saved as cypher.txt successfully!")

    @Slot()
    def upload_file_plain(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Upload File", "", "Text Files (*.txt)",
                                                   options=options)
        if not file_path:
            return
        with open(file_path, 'r') as f:
            self.set_plain_text(f.read())

    @Slot()
    def upload_file_cypher(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Upload File", "", "Text Files (*.txt)",
                                                   options=options)
        if not file_path:
            return
        with open(file_path, 'r') as f:
            self.set_cypher_text(f.read())

    @Slot()
    def encrypt_file_on_click(self):
        if self.encrypting_file:
            self.encrypting_file = False
            self.file_path = ''
            self.encrypt_file.setText('Encrypt File')
            return
        else:
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getOpenFileName(self, "Upload File", "", "All Files (*)",
                                                       options=options)
            if not file_path:
                return
            self.encrypting_file = True
            self.encrypt_file.setText('"' + file_path.split('/')[-1] + '"' + '——取消')
            self.file_path = file_path

    @Slot()
    def decrypt_file_on_click(self):
        if self.decrypting_file:
            self.decrypting_file = False
            self.file_path = ''
            self.decrypt_file.setText('Decrypt File')
            return
        else:
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getOpenFileName(self, "Upload File", "", "DES Files (*.des)",
                                                       options=options)
            if not file_path:
                return
            self.decrypting_file = True
            self.decrypt_file.setText('"' + file_path.split('/')[-1] + '"' + '——取消')
            self.file_path = file_path

    @Slot()
    def clear_plain_text(self):
        self.set_plain_text('')

    @Slot()
    def clear_cypher_text(self):
        self.set_cypher_text('')

    def get_plain_text(self):
        return self.plain_text.toPlainText()

    def set_plain_text(self, text):
        self.plain_text.setText(text)

    def get_cypher_text(self):
        return self.cypher_text.toPlainText()

    def set_cypher_text(self, text):
        self.cypher_text.setText(text)


def start():
    app = QApplication(sys.argv)
    ex = GUI()
    sys.exit(app.exec())


if __name__ == '__main__':
    start()
