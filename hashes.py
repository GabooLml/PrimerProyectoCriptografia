import time
from base64 import b64encode
from base64 import b64decode
from Crypto import Random
from Crypto.Hash import SHA512, SHA3_512
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

class SHA2:
    def __init__(self):
        self.h = SHA512.new()
        self.start_time = None
        self.end_time = None

    def get_value_hash(self, data):
        # Medir el tiempo que tarda en hashear
        self.start_time = time.time()
        self.h.update(data.encode("utf-8"))
        hashvalue = self.h.digest()
        self.end_time = time.time()
        value_b64 = b64encode(hashvalue)
        print(value_b64.decode("utf-8"))
        return hashvalue
    
class SHA3:
    def __init__(self):
        self.h = SHA3_512.new()
        self.start_time = None
        self.end_time = None

    def get_value_hash(self, data):
        # Medir el tiempo que tarda en hashear
        self.start_time = time.time()
        self.h.update(data.encode("utf-8"))
        hashvalue = self.h.digest()
        self.end_time = time.time()
        value_b64 = b64encode(hashvalue)
        print(value_b64.decode("utf-8"))
        return hashvalue
    
class Scrypt:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.salt = get_random_bytes(32)

    def get_key(self, password):
        # Medir el tiempo que tarda en generar la llave
        self.start_time = time.time()
        key = scrypt(password.encode("utf-8"), self.salt, 32, N=2**14, r=8, p=1)
        self.end_time = time.time()
        key_b64 = b64encode(key)
        print(key_b64.decode("utf-8"))
        return key