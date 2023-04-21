import json
import time
from base64 import b64encode
from base64 import b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

BLOCK_SIZE = 32  # Bytes = 16 bits
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class chacha20:
    def __init__(self):
        self.key = get_random_bytes(32)
        self.start_time = None
        self.end_time = None

    def encrypt(self, plaintext):
        # Medir el tiempo que tarda en cifrar
        self.start_time = time.time()
        cipher = ChaCha20.new(key=self.key)
        ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ciphertext).decode('utf-8')
        result = json.dumps({'nonce':nonce, 'ciphertext':ct})
        self.end_time = time.time()
        return result

    def decrypt(self, jsonInput):
        # Medir el tiempo que tarda en descifrar
        self.start_time = time.time()
        try:
            b64 = json.loads(jsonInput)
            nonce = b64decode(b64['nonce'])
            ciphertext = b64decode(b64['ciphertext'])
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            self.end_time = time.time()
            return plaintext.decode('ascii')
        except (ValueError, KeyError):
            print("Incorrect decryption")
            return None
        
class AES256:
    def __init__(self):
        self.key = get_random_bytes(32)
        self.nonce = None
        self.start_time = None
        self.end_time = None

    def encrypt(self, plaintext, mode):
        if mode == "ECB":
            # Medir el tiempo que tarda en cifrar
            self.start_time = time.time()
            raw = pad(plaintext)
            cipher = AES.new(self.key, AES.MODE_ECB)
            ciphertext =  b64encode(cipher.encrypt(raw.encode('utf8')))
            self.end_time = time.time()
            return ciphertext
        elif mode == "GCM":
            # Medir el tiempo que tarda en cifrar
            self.start_time = time.time()
            cipher = AES.new(self.key, AES.MODE_GCM)
            self.nonce = cipher.nonce
            ciphertext = cipher.encrypt(plaintext.encode('utf8'))
            self.end_time = time.time()
            return ciphertext
        else:
            print("Invalid mode")
            return None

    def decrypt(self, ciphertext, mode):
        if mode == "ECB":
            # Medir el tiempo que tarda en descifrar
            self.start_time = time.time()
            ciphertext = b64decode(ciphertext)
            cipher = AES.new(self.key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext)).decode('utf8')
            self.end_time = time.time()
            return plaintext
        elif mode == "GCM":
            # Medir el tiempo que tarda en descifrar
            self.start_time = time.time()
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
            plaintext = cipher.decrypt(ciphertext).decode('utf8')
            self.end_time = time.time()
            return plaintext
        else:
            print("Invalid mode")
            return None

class RSAOAEP:
    def __init__(self):
        self.keyPair = RSA.generate(2048)
        self.pubKey = self.keyPair.publickey()
        self.start_time = None
        self.end_time = None

    def encrypt(self, plaintext):
        # Medir el tiempo que tarda en cifrar
        self.start_time = time.time()
        cipher = PKCS1_OAEP.new(self.pubKey)
        ciphertext = cipher.encrypt(plaintext.encode('utf8'))
        self.end_time = time.time()
        return ciphertext

    def decrypt(self, ciphertext):
        # Medir el tiempo que tarda en descifrar
        self.start_time = time.time()
        cipher = PKCS1_OAEP.new(self.keyPair)
        plaintext = cipher.decrypt(ciphertext)
        self.end_time = time.time()
        return plaintext.decode('utf8')