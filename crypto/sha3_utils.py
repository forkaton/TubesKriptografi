"""
crypto/sha3_utils.py
Modul SHA-3-256 untuk sistem e-health secure messaging.
Menggunakan hashlib (Python Standard Library).
"""
import hashlib
import hmac


def compute_sha3_256(message: str) -> str:
    if not isinstance(message, str):
        raise TypeError('message harus berupa string')
    return hashlib.sha3_256(message.encode('utf-8')).hexdigest()


def verify_sha3_256(message: str, expected_digest: str) -> bool:
    computed = compute_sha3_256(message)
    return hmac.compare_digest(computed, expected_digest)


def compute_avalanche_effect(msg1: str, msg2: str) -> dict:
    d1 = compute_sha3_256(msg1)
    d2 = compute_sha3_256(msg2)
    bits1 = bin(int(d1, 16))[2:].zfill(256)
    bits2 = bin(int(d2, 16))[2:].zfill(256)
    changed = sum(a != b for a, b in zip(bits1, bits2))
    return {
        'bits_changed': changed,
        'total_bits': 256,
        'percentage': round((changed / 256) * 100.0, 2),
        'digest1': d1,
        'digest2': d2
    }
