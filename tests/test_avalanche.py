"""
tests/test_avalanche.py
Evaluasi Avalanche Effect dan Collision Resistance
Kelompok 7 — Kriptografi Genap 2026
"""
import sys
import os
import time
import secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto.sha3_utils    import compute_sha3_256, compute_avalanche_effect
from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm

def test_avalanche_sha3(iterations=100):
    print('\n=== E4: Avalanche Effect SHA-3-256 ===')
    results = []
    base = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    for i in range(iterations):
        chars = list(base)
        pos = i % len(base)
        chars[pos] = chr(ord(chars[pos]) ^ 1)
        modified = ''.join(chars)
        ae = compute_avalanche_effect(base, modified)
        results.append(ae['percentage'])
    mean = sum(results) / len(results)
    variance = sum((x - mean)**2 for x in results) / len(results)
    std = variance ** 0.5
    print(f'Iterasi  : {iterations}')
    print(f'Mean     : {mean:.2f}% (target: ~50%)')
    print(f'Std Dev  : {std:.2f}%')
    print(f'Min      : {min(results):.2f}%')
    print(f'Max      : {max(results):.2f}%')
    print(f'SAC OK   : {40 <= mean <= 60}')
    return mean

def test_collision_resistance(pairs=10000):
    print('\n=== H2: Collision Resistance SHA-3-256 ===')
    seen = set()
    collisions = 0
    for i in range(pairs):
        msg = secrets.token_hex(16 + (i % 32))
        h = compute_sha3_256(msg)
        if h in seen:
            collisions += 1
        seen.add(h)
    print(f'Pasang diuji : {pairs}')
    print(f'Collision    : {collisions}')
    print(f'Zero Collision: {collisions == 0}')
    return collisions

def test_aes_avalanche(iterations=100):
    print('\n=== E1: Avalanche Effect AES-256-GCM ===')
    key = generate_key()
    base = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    results = []
    for i in range(iterations):
        iv1, ct1, _ = encrypt_aes_gcm(key, base)
        chars = list(base)
        chars[i % len(base)] = chr(ord(chars[i % len(base)]) ^ 1)
        modified = ''.join(chars)
        iv2, ct2, _ = encrypt_aes_gcm(key, modified)
        min_len = min(len(ct1), len(ct2))
        bits1 = ''.join(bin(b)[2:].zfill(8) for b in ct1[:min_len])
        bits2 = ''.join(bin(b)[2:].zfill(8) for b in ct2[:min_len])
        changed = sum(a != b for a, b in zip(bits1, bits2))
        total = min_len * 8
        results.append((changed / total) * 100)
    mean = sum(results) / len(results)
    print(f'Iterasi  : {iterations}')
    print(f'Mean     : {mean:.2f}% (target: ~50%)')
    print(f'SAC OK   : {40 <= mean <= 60}')
    return mean

def test_performance():
    print('\n=== E3: Waktu Komputasi AES-256-GCM ===')
    key = generate_key()
    sizes = [50, 100, 500, 1000, 5000]
    for size in sizes:
        msg = 'A' * size
        times = []
        for _ in range(100):
            t0 = time.perf_counter()
            encrypt_aes_gcm(key, msg)
            times.append((time.perf_counter() - t0) * 1000)
        mean_ms = sum(times) / len(times)
        print(f'  {size:5d} karakter: {mean_ms:.3f} ms (target < 5ms)')

if __name__ == '__main__':
    test_avalanche_sha3()
    test_collision_resistance()
    test_aes_avalanche()
    test_performance()
    print('\n=== Semua pengujian selesai ===')
