import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QGroupBox, QComboBox, QSpinBox,
    QLabel, QPushButton, QTextEdit, QLineEdit, QGridLayout, QVBoxLayout,
    QFileDialog, QMessageBox
)
from hashing import sha
import signature.rsa as rsa_alg
import signature.dsa as dsa_alg
import signature.elgamal as elgamal_alg
from utils import file_ops, logger

class DigitalSignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Signature Application")
        self.algorithms = {"RSA": rsa_alg, "DSA": dsa_alg, "ElGamal": elgamal_alg}
        self.public_key = None
        self.private_key = None
        self.public_params = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        group_algo = QGroupBox("Algorithm Selection")
        grid_algo = QGridLayout()
        group_algo.setLayout(grid_algo)

        grid_algo.addWidget(QLabel("Signature Algorithm:"), 0, 0)
        self.combo_sig = QComboBox()
        self.combo_sig.addItems(self.algorithms.keys())
        grid_algo.addWidget(self.combo_sig, 0, 1)

        grid_algo.addWidget(QLabel("Hash Algorithm:"), 1, 0)
        self.combo_hash = QComboBox()
        self.combo_hash.addItems(["SHA-256", "SHA-384", "SHA-512"])
        grid_algo.addWidget(self.combo_hash, 1, 1)

        grid_algo.addWidget(QLabel("Key Length (bits):"), 2, 0)
        self.spin_key = QSpinBox()
        self.spin_key.setRange(512, 16384)
        self.spin_key.setValue(1024)
        grid_algo.addWidget(self.spin_key, 2, 1)

        layout.addWidget(group_algo)

        group_keys = QGroupBox("Key Generation")
        grid_keys = QGridLayout()
        group_keys.setLayout(grid_keys)

        btn_gen = QPushButton("Generate Keys")
        btn_gen.clicked.connect(self.generate_keys)
        grid_keys.addWidget(btn_gen, 0, 0)

        btn_save_pub = QPushButton("Save Public Key")
        btn_save_pub.clicked.connect(self.save_public_key)
        grid_keys.addWidget(btn_save_pub, 0, 1)

        btn_save_priv = QPushButton("Save Private Key")
        btn_save_priv.clicked.connect(self.save_private_key)
        grid_keys.addWidget(btn_save_priv, 0, 2)

        self.text_public = QTextEdit()
        self.text_public.setReadOnly(True)
        grid_keys.addWidget(self.text_public, 1, 0, 1, 3)

        self.text_private = QTextEdit()
        self.text_private.setReadOnly(True)
        grid_keys.addWidget(self.text_private, 2, 0, 1, 3)

        layout.addWidget(group_keys)

        group_sign = QGroupBox("Digital Signature Creation")
        grid_sign = QGridLayout()
        group_sign.setLayout(grid_sign)

        grid_sign.addWidget(QLabel("Message:"), 0, 0)
        self.text_message = QTextEdit()
        grid_sign.addWidget(self.text_message, 1, 0, 1, 3)

        btn_sign = QPushButton("Sign Message")
        btn_sign.clicked.connect(self.sign_message)
        grid_sign.addWidget(btn_sign, 2, 0)

        btn_save_sig = QPushButton("Save Signature")
        btn_save_sig.clicked.connect(self.save_signature)
        grid_sign.addWidget(btn_save_sig, 2, 1)

        self.text_signature = QTextEdit()
        self.text_signature.setReadOnly(True)
        grid_sign.addWidget(self.text_signature, 3, 0, 1, 3)

        layout.addWidget(group_sign)

        group_verify = QGroupBox("Digital Signature Verification")
        grid_verify = QGridLayout()
        group_verify.setLayout(grid_verify)

        grid_verify.addWidget(QLabel("Message:"), 0, 0)
        self.text_verify_msg = QTextEdit()
        grid_verify.addWidget(self.text_verify_msg, 1, 0, 1, 3)

        grid_verify.addWidget(QLabel("Signature:"), 2, 0)
        self.line_signature = QLineEdit()
        grid_verify.addWidget(self.line_signature, 3, 0, 1, 3)

        btn_verify = QPushButton("Verify Signature")
        btn_verify.clicked.connect(self.verify_signature)
        grid_verify.addWidget(btn_verify, 4, 0)

        self.label_result = QLabel()
        grid_verify.addWidget(self.label_result, 4, 1)

        layout.addWidget(group_verify)

        self.setLayout(layout)

    def generate_keys(self):
        algo = self.combo_sig.currentText()
        bits = self.spin_key.value()
        try:
            if algo == "RSA":
                self.public_key, self.private_key = self.algorithms[algo].generate_keys(bits=bits)
                self.public_params = None
            elif algo == "DSA":
                self.public_key, self.private_key = self.algorithms[algo].generate_keys(L=bits, N=160)
                self.public_params = self.public_key
            else:  # ElGamal
                self.public_key, self.private_key = self.algorithms[algo].generate_keys(bits=bits)
                self.public_params = self.public_key
            self.text_public.setPlainText(str(self.public_key))
            self.text_private.setPlainText(str(self.private_key))
            logger.log(f"Keys generated using {algo}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            logger.log("Error generating keys: " + str(e))

    def save_public_key(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Public Key", filter="Text Files (*.txt)")
        if path:
            file_ops.save_to_file(path, self.text_public.toPlainText())
            logger.log(f"Public key saved to {path}")

    def save_private_key(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Private Key", filter="Text Files (*.txt)")
        if path:
            file_ops.save_to_file(path, self.text_private.toPlainText())
            logger.log(f"Private key saved to {path}")

    def sign_message(self):
        msg = self.text_message.toPlainText().strip()
        if not msg:
            QMessageBox.warning(self, "Error", "Message is empty")
            return
        hash_algo = self.combo_hash.currentText()
        try:
            hash_int = sha.compute_hash(msg, hash_algo)
        except Exception as e:
            QMessageBox.critical(self, "Error", "Hashing failed: " + str(e))
            return
        algo = self.combo_sig.currentText()
        try:
            if algo == "RSA":
                signature = self.algorithms[algo].sign(msg, self.private_key, hash_int)
            elif algo == "DSA":
                signature = self.algorithms[algo].sign(msg, self.private_key, self.public_key, hash_int)
            else:
                signature = self.algorithms[algo].sign(msg, self.private_key, self.public_key, hash_int)
            self.text_signature.setPlainText(str(signature))
            logger.log(f"Message signed using {algo}")
        except Exception as e:
            QMessageBox.critical(self, "Error", "Signing failed: " + str(e))
            logger.log("Error signing message: " + str(e))

    def save_signature(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Signature", filter="Text Files (*.txt)")
        if path:
            file_ops.save_to_file(path, self.text_signature.toPlainText())
            logger.log(f"Signature saved to {path}")

    def verify_signature(self):
        msg = self.text_verify_msg.toPlainText().strip()
        sig_str = self.line_signature.text().strip()
        if not msg or not sig_str:
            QMessageBox.warning(self, "Error", "Message or signature is empty")
            return
        try:
            signature = eval(sig_str)
        except Exception:
            QMessageBox.critical(self, "Error", "Invalid signature format")
            return
        hash_algo = self.combo_hash.currentText()
        try:
            hash_int = sha.compute_hash(msg, hash_algo)
        except Exception:
            QMessageBox.critical(self, "Error", "Hashing failed: " + str(e))
            return
        algo = self.combo_sig.currentText()
        try:
            valid = self.algorithms[algo].verify(msg, signature, self.public_key, hash_int)
            result = "Valid Signature" if valid else "Invalid Signature"
            self.label_result.setText(result)
            logger.log("Verification result: " + result)
        except Exception as e:
            QMessageBox.critical(self, "Error", "Verification failed: " + str(e))
            logger.log("Error verifying signature: " + str(e))

