from crypto.sha3_utils import compute_sha3_256, compute_avalanche_effect

# Test 1: nilai harus PERSIS ini
plaintext = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
expected = '5d83bd5fdde7eae383536a48f0fc7f0efa9718c5f3ad8d8564d8b8bdffecea9c'
result = compute_sha3_256(plaintext)
print('SHA-3-256 MATCH:', result == expected)
print('Digest:', result)

# Test 2: avalanche effect
p2 = plaintext.replace('5 hari', '6 hari')
ae = compute_avalanche_effect(plaintext, p2)
print(f'Avalanche Effect: {ae["bits_changed"]}/256 bit = {ae["percentage"]}%')
print('SAC OK:', 40 <= ae['percentage'] <= 60)
