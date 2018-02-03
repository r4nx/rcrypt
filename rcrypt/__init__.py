#!/usr/bin/python
# -*- coding: utf-8 -*-

# rcrypt - wrapper for pycryptodomex
# Copyright (C) 2018  Ranx

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import os
import struct

import Cryptodome
from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import Blowfish
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Protocol import KDF
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5


class AESCipher(object):
    """AES cipher, 256-bit key, 128-bit block, EAX mode

    Args:
        key (str): Encryption key
        salt (str): Salt
    """

    def __init__(self, key, salt):
        self.__key = KDF.PBKDF2(password=key, salt=salt.encode(), dkLen=32, count=10000, prf=_prf)

    def encrypt(self, plaintext):
        """Encrypts the plaintext

        Args:
            plaintext (str): Plaintext to encrypt

        Returns:
            str: Encrypted text
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        cipher = AES.new(key=self.__key, mode=AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """Decrypts the encrypted text

        Args:
            ciphertext (str): Encrypted text to decrypt

        Returns:
            str: Decrypted text
        """
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:16]
        tag = ciphertext[16:32]
        ciphertext = ciphertext[32:]
        cipher = AES.new(key=self.__key, mode=AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Encrypts the file

        Args:
            in_file_name (str): File to encrypt
            out_file_name (str or None): Name of encrypted file (default is in_file_name + .enc) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher = AES.new(key=self.__key, mode=AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Decrypts the file

        Args:
            in_file_name (str): File to decrypt
            out_file_name (str or None): Name of decrypted file (default is in_file_name without extension,
                if in_file_name has no extension, than in_file_name + .decrypted) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 16, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher = AES.new(key=self.__key, mode=AES.MODE_EAX, nonce=nonce)

                    out_file.write(cipher.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


class BlowfishCipher(object):
    """Blowfish cipher, 256-bit key, 64-bit block, EAX mode

    Args:
        key (str): Encryption key
        salt (str): Salt
    """

    def __init__(self, key, salt):
        self.__key = KDF.PBKDF2(password=key, salt=salt.encode(), dkLen=32, count=10000, prf=_prf)

    def encrypt(self, plaintext):
        """Encrypts the plaintext

        Args:
            plaintext (str): Plaintext to encrypt

        Returns:
            str: Encrypted text
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        cipher = Blowfish.new(key=self.__key, mode=Blowfish.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """Decrypts the encrypted text

        Args:
            ciphertext (str): Encrypted text to decrypt

        Returns:
            str: Decrypted text
        """
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:16]
        tag = ciphertext[16:24]
        ciphertext = ciphertext[24:]
        cipher = Blowfish.new(key=self.__key, mode=Blowfish.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Encrypts the file

        Args:
            in_file_name (str): File to encrypt
            out_file_name (str or None): Name of encrypted file (default is in_file_name + .enc) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher = Blowfish.new(key=self.__key, mode=Blowfish.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Decrypts the file

        Args:
            in_file_name (str): File to decrypt
            out_file_name (str or None): Name of decrypted file (default is in_file_name without extension,
                if in_file_name has no extension, than in_file_name + .decrypted) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 8, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher = Blowfish.new(key=self.__key, mode=Blowfish.MODE_EAX, nonce=nonce)

                    out_file.write(cipher.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


class RSACipher(object):
    """RSA cipher

    Args:
        public_key_loc (str or None): Path to public key file (required for encryption and verification) [optional]
        private_key_loc (str or None): Path to private key file (required for decryption and signature) [optional]
        public_key_passphrase (str or None): Public key passphrase, if exists [optional]
        private_key_passphrase (str or None): Private key passphrase, if exists [optional]
    """

    def __init__(self, public_key_loc=None, private_key_loc=None,
                 public_key_passphrase=None, private_key_passphrase=None):
        self.__public_key_loc = public_key_loc
        self.__private_key_loc = private_key_loc
        self.__public_key_passphrase = public_key_passphrase
        self.__private_key_passphrase = private_key_passphrase

    def generate_keys(self, keys_size=2048, public_key_format='PEM', private_key_format='PEM'):
        """Generates new RSA keys

        Args:
            keys_size (int or None): Keys size (default is 2048) [optional]
            public_key_format (str or None): Public key format (default is PEM) [optional]
            private_key_format (str or None): Private key format (default is PEM) [optional]

        Note:
            Keys formats:

            - **PEM** (default) - text encoding
            - **DER** - binary encoding
            - **OpenSSH**  - textual encoding, done according to OpenSSH specification. Only suitable for public keys.

        """
        random_generator = Random.new().read
        keys = RSA.generate(keys_size, random_generator)

        with open(self.__public_key_loc, 'wb') as public_key_file:
            public_key_file.write(keys.publickey().exportKey(
                format=public_key_format, passphrase=self.__public_key_passphrase))

        with open(self.__private_key_loc, 'wb') as private_key_file:
            private_key_file.write(keys.exportKey(format=private_key_format, passphrase=self.__private_key_passphrase))

    def encrypt(self, plaintext):
        """Encrypts the plaintext

        Args:
            plaintext (str): Plaintext to encrypt

        Returns:
            str: Encrypted text
        """
        with open(self.__public_key_loc, 'rb') as public_key_file:
            cipher = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.__public_key_passphrase))

        return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

    def decrypt(self, ciphertext):
        """Decrypts the encrypted text

        Args:
            ciphertext (str): Encrypted text to decrypt

        Returns:
            str: Decrypted text
        """
        with open(self.__private_key_loc, 'rb') as private_key_file:
            cipher = PKCS1_OAEP.new(RSA.import_key(private_key_file.read(), passphrase=self.__private_key_passphrase))

        return cipher.decrypt(base64.b64decode(ciphertext.encode())).decode()

    def sign(self, data):
        """Signs the data

        Args:
            data (str): Text to sign

        Returns:
            str: Signature
        """
        with open(self.__private_key_loc, 'rb') as private_key_file:
            signer = PKCS1_v1_5.new(RSA.import_key(private_key_file.read(), passphrase=self.__private_key_passphrase))
        digest = SHA256.new(data.encode())

        return base64.b64encode(signer.sign(digest)).decode()

    def verify(self, signature, data):
        """Verifies text signature

        Args:
            signature (str): Signature to verify
            data (str): Signed text

        Returns:
            bool: True if signature valid, false if not.
        """
        with open(self.__public_key_loc, 'rb') as public_key_file:
            signer = PKCS1_v1_5.new(RSA.import_key(public_key_file.read(), passphrase=self.__public_key_passphrase))
        digest = SHA256.new(data.encode())

        if signer.verify(digest, base64.b64decode(signature)):
            return True
        return False


class HybridAESRSACipher(object):
    """Hybrid AES-RSA cipher

    Encryption: rcrypt encrypts data with 256-bit AES (EAX mode),
    then encrypts AES key with RSA public key and appends it to the data.

    Decryption: rcrypt gets AES key from the ciphertext,
    decrypts it with RSA private key and then decrypts the encrypted data with AES key.

    Args:
        public_key_loc (str or None): Path to public key file (required for encryption and verification) [optional]
        private_key_loc (str or None): Path to private key file (required for decryption and signature) [optional]
        public_key_passphrase (str or None): Public key passphrase, if exists [optional]
        private_key_passphrase (str or None): Private key passphrase, if exists [optional]
    """

    def __init__(self, public_key_loc=None, private_key_loc=None,
                 public_key_passphrase=None, private_key_passphrase=None):
        self.__public_key_loc = public_key_loc
        self.__private_key_loc = private_key_loc
        self.__public_key_passphrase = public_key_passphrase
        self.__private_key_passphrase = private_key_passphrase

    def generate_keys(self, keys_size=2048, public_key_format='PEM', private_key_format='PEM'):
        """Generates new RSA keys

        Args:
            keys_size (int or None): Keys size (default is 2048) [optional]
            public_key_format (str or None): Public key format (default is PEM) [optional]
            private_key_format (str or None): Private key format (default is PEM) [optional]

        Note:
            Keys formats:

            - **PEM** (default) - text encoding
            - **DER** - binary encoding
            - **OpenSSH**  - textual encoding, done according to OpenSSH specification. Only suitable for public keys.

        """
        random_generator = Random.new().read
        keys = RSA.generate(keys_size, random_generator)

        with open(self.__public_key_loc, 'wb') as public_key_file:
            public_key_file.write(keys.publickey().exportKey(
                format=public_key_format, passphrase=self.__public_key_passphrase))

        with open(self.__private_key_loc, 'wb') as private_key_file:
            private_key_file.write(keys.exportKey(format=private_key_format, passphrase=self.__private_key_passphrase))

    def encrypt(self, plaintext):
        """Encrypts the plaintext

        Args:
            plaintext (str): Plaintext to encrypt

        Returns:
            str: Encrypted text
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        session_key = Random.get_random_bytes(32)

        with open(self.__public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.__public_key_passphrase))

        cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        return base64.b64encode(cipher_rsa.encrypt(session_key) + cipher_aes.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """Decrypts the encrypted text

        Args:
            ciphertext (str): Encrypted text to decrypt

        Returns:
            str: Decrypted text
        """
        with open(self.__private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.__private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        ciphertext = base64.b64decode(ciphertext)
        session_key = cipher_rsa.decrypt(ciphertext[:private_key.size_in_bytes()])
        nonce = ciphertext[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
        tag = ciphertext[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32]

        ciphertext = ciphertext[private_key.size_in_bytes() + 32:]
        cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Encrypts the file

        Args:
            in_file_name (str): File to encrypt
            out_file_name (str or None): Name of encrypted file (default is in_file_name + .enc) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)
        session_key = Random.get_random_bytes(32)

        with open(self.__public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.__public_key_passphrase))
        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))
                out_file.write(cipher_rsa.encrypt(session_key))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX)
                    ciphertext, tag = cipher_aes.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Decrypts the file

        Args:
            in_file_name (str): File to decrypt
            out_file_name (str or None): Name of decrypted file (default is in_file_name without extension,
                if in_file_name has no extension, than in_file_name + .decrypted) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(self.__private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.__private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]
                session_key = cipher_rsa.decrypt(in_file.read(private_key.size_in_bytes()))

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 16, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX, nonce=nonce)

                    out_file.write(cipher_aes.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


class HybridBlowfishRSACipher(object):
    """Hybrid AES-RSA cipher

    Encryption: rcrypt encrypts data with 256-bit Blowfish (EAX mode),
    then encrypts Blowfish key with RSA public key and appends it to the data.

    Decryption: rcrypt gets Blowfish key from the ciphertext,
    decrypts it with RSA private key and then decrypts the encrypted data with Blowfish key.

    Args:
        public_key_loc (str or None): Path to public key file (required for encryption and verification) [optional]
        private_key_loc (str or None): Path to private key file (required for decryption and signature) [optional]
        public_key_passphrase (str or None): Public key passphrase, if exists [optional]
        private_key_passphrase (str or None): Private key passphrase, if exists [optional]
    """

    def __init__(self, public_key_loc=None, private_key_loc=None,
                 public_key_passphrase=None, private_key_passphrase=None):
        self.__public_key_loc = public_key_loc
        self.__private_key_loc = private_key_loc
        self.__public_key_passphrase = public_key_passphrase
        self.__private_key_passphrase = private_key_passphrase

    def generate_keys(self, keys_size=2048, public_key_format='PEM', private_key_format='PEM'):
        """Generates new RSA keys

        Args:
            keys_size (int or None): Keys size (default is 2048) [optional]
            public_key_format (str or None): Public key format (default is PEM) [optional]
            private_key_format (str or None): Private key format (default is PEM) [optional]

        Note:
            Keys formats:

            - **PEM** (default) - text encoding
            - **DER** - binary encoding
            - **OpenSSH**  - textual encoding, done according to OpenSSH specification. Only suitable for public keys.

        """
        random_generator = Random.new().read
        keys = RSA.generate(keys_size, random_generator)

        with open(self.__public_key_loc, 'wb') as public_key_file:
            public_key_file.write(keys.publickey().exportKey(
                format=public_key_format, passphrase=self.__public_key_passphrase))

        with open(self.__private_key_loc, 'wb') as private_key_file:
            private_key_file.write(keys.exportKey(format=private_key_format, passphrase=self.__private_key_passphrase))

    def encrypt(self, plaintext):
        """Encrypts the plaintext

        Args:
            plaintext (str): Plaintext to encrypt

        Returns:
            str: Encrypted text
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        session_key = Random.get_random_bytes(32)

        with open(self.__public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.__public_key_passphrase))

        cipher_blowfish = Blowfish.new(key=session_key, mode=Blowfish.MODE_EAX)
        ciphertext, tag = cipher_blowfish.encrypt_and_digest(plaintext)

        return base64.b64encode(cipher_rsa.encrypt(session_key) + cipher_blowfish.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """Decrypts the encrypted text

        Args:
            ciphertext (str): Encrypted text to decrypt

        Returns:
            str: Decrypted text
        """
        with open(self.__private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.__private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        ciphertext = base64.b64decode(ciphertext)
        session_key = cipher_rsa.decrypt(ciphertext[:private_key.size_in_bytes()])
        nonce = ciphertext[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
        tag = ciphertext[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 24]

        ciphertext = ciphertext[private_key.size_in_bytes() + 24:]
        cipher_blowfish = Blowfish.new(key=session_key, mode=Blowfish.MODE_EAX, nonce=nonce)
        plaintext = cipher_blowfish.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Encrypts the file

        Args:
            in_file_name (str): File to encrypt
            out_file_name (str or None): Name of encrypted file (default is in_file_name + .enc) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)
        session_key = Random.get_random_bytes(32)

        with open(self.__public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.__public_key_passphrase))
        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))
                out_file.write(cipher_rsa.encrypt(session_key))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher_blowfish = Blowfish.new(key=session_key, mode=Blowfish.MODE_EAX)
                    ciphertext, tag = cipher_blowfish.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher_blowfish.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """Decrypts the file

        Args:
            in_file_name (str): File to decrypt
            out_file_name (str or None): Name of decrypted file (default is in_file_name without extension,
                if in_file_name has no extension, than in_file_name + .decrypted) [optional]
            chunk_size (int or None): The number of bytes that will be read at a time (default is 65536) [optional]
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(self.__private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.__private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]
                session_key = cipher_rsa.decrypt(in_file.read(private_key.size_in_bytes()))

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 8, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher_blowfish = Blowfish.new(key=session_key, mode=Blowfish.MODE_EAX, nonce=nonce)

                    out_file.write(cipher_blowfish.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


def _pad(s, bs):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode()


def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def _prf(p, s):
    return HMAC.new(p, s, Cryptodome.Hash.SHA256).digest()
