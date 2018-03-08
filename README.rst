rcrypt
======

rcrypt is a wrapper for pycryptodomex. No need to write 10 lines of code to encrypt one single string, rcrypt do it for you.

Installation
------------

You can install rcrypt with pip::

    pip install rcrypt

Available ciphers
-----------------

- AES
- Blowfish
- RSA (messages only)
- Hybrid AES-RSA
- Hybrid Blowfish-RSA

Examples
--------

**AES message encryption**:
  .. code:: python

    import rcrypt
    cipher = rcrypt.AESCipher('password', 'salt')
    ciphertext = cipher.encrypt('My secret message')

**Blowfish file encryption**:
  .. code:: python

    import rcrypt
    cipher = rcrypt.BlowfishCipher('password', 'salt')
    cipher.encrypt_file('secret_document.txt')

**RSA message encryption**:
  .. code:: python

    import rcrypt
    cipher = rcrypt.RSACipher('public_key.pem')
    ciphertext = cipher.encrypt('My secret message')

**Hybrid AES-RSA file encryption**:
  .. code:: python

    import rcrypt
    aesrsa = rcrypt.HybridAESRSACipher('public.key', 'private_key')
    aesrsa.encrypt_file('secret_document.txt')

Documentation
-------------

Full documentation can be found `here <https://rcrypt.readthedocs.io>`_.
