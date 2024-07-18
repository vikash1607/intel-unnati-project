from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os

def derive_key(passphrase, salt, iterations=100000):
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations)

def encrypt_file(file_path, passphrase):
    salt = get_random_bytes(16)
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + cipher.nonce + tag + ciphertext)
    
    protected_key = AES.new(derive_key(passphrase, salt), AES.MODE_GCM).encrypt(key)
    
    with open('key.enc', 'wb') as f:
        f.write(salt + protected_key)

def decrypt_file(file_path, passphrase):
    with open('key.enc', 'rb') as f:
        salt = f.read(16)
        protected_key = f.read()
    
    key = AES.new(derive_key(passphrase, salt), AES.MODE_GCM).decrypt(protected_key)
    
    with open(file_path + '.enc', 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    with open(file_path, 'wb') as f:
        f.write(plaintext)
