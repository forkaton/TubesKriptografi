"""
crypto/aes_gcm_utils.py
Modul AES-256-GCM untuk sistem e-health secure messaging.
Menggunakan PyCryptodome.
"""
import os
from Crypto.Cipher import AES

IV_SIZE  = 12
TAG_SIZE = 16
KEY_SIZE = 32


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def encrypt_aes_gcm(key: bytes, plaintext: str) -> tuple:
    if len(key) != KEY_SIZE:
        raise ValueError(f'Kunci AES-256 harus tepat {KEY_SIZE} byte, diberikan {len(key)} byte')
    iv = os.urandom(IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return iv, ciphertext, auth_tag


def decrypt_aes_gcm(key: bytes, iv: bytes, ciphertext: bytes, auth_tag: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
    return plaintext_bytes.decode('utf-8')


def build_packet(iv: bytes, auth_tag: bytes, ciphertext: bytes) -> bytes:
    return iv + auth_tag + ciphertext


def parse_packet(packet: bytes) -> tuple:
    min_len = IV_SIZE + TAG_SIZE
    if len(packet) < min_len:
        raise ValueError(f'Paket terlalu pendek: {len(packet)} byte (minimum {min_len})')
    iv         = packet[:IV_SIZE]
    auth_tag   = packet[IV_SIZE : IV_SIZE + TAG_SIZE]
    ciphertext = packet[IV_SIZE + TAG_SIZE:]
    return iv, auth_tag, ciphertext
