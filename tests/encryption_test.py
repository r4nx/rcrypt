# Pytest test suite. You can run it with "python -m pytest rcrypt_test.py" or "pytest rcrypt_test.py" command.

import hashlib

import rcrypt


def test_aes_message_encryption():
    plaintext = 'AES encryption test'
    aes = rcrypt.AESCipher('123321', '12345')
    ciphertext = aes.encrypt(plaintext)
    decrypted = aes.decrypt(ciphertext)
    assert decrypted == plaintext


def test_aes_file_encryption(tmpdir):
    aes = rcrypt.AESCipher('123321', '12345')
    aes.encrypt_file('tests/test_file.txt', str(tmpdir.join('test_file.txt.enc')))
    aes.decrypt_file(str(tmpdir.join('test_file.txt.enc')), str(tmpdir.join('test_file.txt.decrypted')))
    assert hash_file('tests/test_file.txt') == hash_file(str(tmpdir.join('test_file.txt.decrypted')))


def test_blowfish_message_encryption():
    plaintext = 'Blowfish encryption test'
    blowfish = rcrypt.BlowfishCipher('123321', '12345')
    ciphertext = blowfish.encrypt(plaintext)
    decrypted = blowfish.decrypt(ciphertext)
    assert decrypted == plaintext


def test_blowfish_file_encryption(tmpdir):
    blowfish = rcrypt.BlowfishCipher('123321', '12345')
    blowfish.encrypt_file('tests/test_file.txt', str(tmpdir.join('test_file.txt.enc')))
    blowfish.decrypt_file(str(tmpdir.join('test_file.txt.enc')), str(tmpdir.join('test_file.txt.decrypted')))
    assert hash_file('tests/test_file.txt') == hash_file(str(tmpdir.join('test_file.txt.decrypted')))


def test_rsa_message_encryption(tmpdir):
    plaintext = 'RSA encryption test'
    rsa = rcrypt.RSACipher(str(tmpdir.join('public.key')), str(tmpdir.join('private.key')))
    rsa.generate_keys(keys_size=1024)
    rsa.generate_keys(keys_size=2048)
    rsa.generate_keys(keys_size=3072)
    rsa.generate_keys(keys_size=2048, public_key_format='DER', private_key_format='DER')
    rsa.generate_keys(keys_size=2048, public_key_format='OpenSSH', private_key_format='DER')
    ciphertext = rsa.encrypt(plaintext)
    decrypted = rsa.decrypt(ciphertext)
    assert decrypted == plaintext


def test_rsa_signature(tmpdir):
    message = 'RSA signature test'
    rsa = rcrypt.RSACipher(str(tmpdir.join('public.key')), str(tmpdir.join('private.key')))
    rsa.generate_keys()
    signature = rsa.sign(message)
    assert rsa.verify(signature, message)


def test_hybridaesrsa_message_encryption(tmpdir):
    plaintext = 'AESRSA encryption test'
    aesrsa = rcrypt.HybridAESRSACipher(str(tmpdir.join('public.key')), str(tmpdir.join('private.key')))
    aesrsa.generate_keys(keys_size=1024)
    aesrsa.generate_keys(keys_size=2048)
    aesrsa.generate_keys(keys_size=3072)
    aesrsa.generate_keys(keys_size=2048, public_key_format='DER', private_key_format='DER')
    aesrsa.generate_keys(keys_size=2048, public_key_format='OpenSSH', private_key_format='DER')
    ciphertext = aesrsa.encrypt(plaintext)
    decrypted = aesrsa.decrypt(ciphertext)
    assert decrypted == plaintext


def test_hybridaesrsa_file_encryption(tmpdir):
    aesrsa = rcrypt.HybridAESRSACipher(str(tmpdir.join('public.key')), str(tmpdir.join('private.key')))
    aesrsa.generate_keys()
    aesrsa.encrypt_file('tests/test_file.txt', str(tmpdir.join('test_file.txt.enc')))
    aesrsa.decrypt_file(str(tmpdir.join('test_file.txt.enc')), str(tmpdir.join('test_file.txt.decrypted')))
    assert hash_file('tests/test_file.txt') == hash_file(str(tmpdir.join('test_file.txt.decrypted')))


def test_hybridblowfishrsa_message_encryption(tmpdir):
    plaintext = 'BlowfishRSA encryption test'
    blowfishrsa = rcrypt.HybridBlowfishRSACipher(str(tmpdir.join('public.key')), str(tmpdir.join('private.key')))
    blowfishrsa.generate_keys(keys_size=1024)
    blowfishrsa.generate_keys(keys_size=2048)
    blowfishrsa.generate_keys(keys_size=3072)
    blowfishrsa.generate_keys(keys_size=2048, public_key_format='DER', private_key_format='DER')
    blowfishrsa.generate_keys(keys_size=2048, public_key_format='OpenSSH', private_key_format='DER')
    ciphertext = blowfishrsa.encrypt(plaintext)
    decrypted = blowfishrsa.decrypt(ciphertext)
    assert decrypted == plaintext


def test_hybridblowfishrsa_file_encryption(tmpdir):
    blowfishrsa = rcrypt.HybridBlowfishRSACipher(str(tmpdir.join('public.key')), str(tmpdir.join('private.key')))
    blowfishrsa.generate_keys()
    blowfishrsa.encrypt_file('tests/test_file.txt', str(tmpdir.join('test_file.txt.enc')))
    blowfishrsa.decrypt_file(str(tmpdir.join('test_file.txt.enc')), str(tmpdir.join('test_file.txt.decrypted')))
    assert hash_file('tests/test_file.txt') == hash_file(str(tmpdir.join('test_file.txt.decrypted')))


def hash_file(file_name):
    block_size = 65536
    hasher = hashlib.sha1()
    with open(file_name, 'rb') as file:
        buffer = file.read(block_size)
        while len(buffer) > 0:
            hasher.update(buffer)
            buffer = file.read(block_size)
    return hasher.hexdigest()
