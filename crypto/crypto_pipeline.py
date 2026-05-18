"""
crypto/crypto_pipeline.py
Pipeline kriptografi: SHA-3-256 + AES-256-GCM
"""
from .sha3_utils    import compute_sha3_256, verify_sha3_256
from .aes_gcm_utils import encrypt_aes_gcm, decrypt_aes_gcm, build_packet, parse_packet

SEPARATOR = '||HASH||'


def secure_encrypt(key: bytes, message: str) -> bytes:
    digest  = compute_sha3_256(message)
    payload = message + SEPARATOR + digest
    iv, ciphertext, auth_tag = encrypt_aes_gcm(key, payload)
    return build_packet(iv, auth_tag, ciphertext)


def secure_decrypt(key: bytes, packet: bytes) -> dict:
    try:
        iv, auth_tag, ciphertext = parse_packet(packet)
    except ValueError as e:
        return {'message': None, 'is_valid': False, 'error': f'GAGAL PARSE: {e}'}

    try:
        payload = decrypt_aes_gcm(key, iv, ciphertext, auth_tag)
    except ValueError:
        return {'message': None, 'is_valid': False,
                'error': 'GAGAL: Auth Tag tidak cocok — pesan ditolak (indikasi MITM)'}

    if SEPARATOR not in payload:
        return {'message': None, 'is_valid': False,
                'error': 'GAGAL: Format payload tidak valid'}

    parts         = payload.split(SEPARATOR, 1)
    message_dec   = parts[0]
    hash_received = parts[1]

    if not verify_sha3_256(message_dec, hash_received):
        return {'message': None, 'is_valid': False,
                'error': 'GAGAL: Hash SHA-3-256 tidak cocok — integritas gagal'}

    return {'message': message_dec, 'is_valid': True, 'error': None}
