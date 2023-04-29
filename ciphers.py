import json
import time
from base64 import b64encode
from base64 import b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

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
        print(ciphertext)
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
            print(plaintext)
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
            cipher = AES.new(self.key, AES.MODE_ECB)
            ciphertext =  cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            self.end_time = time.time()
            print(ciphertext)
            return ciphertext
        elif mode == "GCM":
            # Medir el tiempo que tarda en cifrar
            self.start_time = time.time()
            cipher = AES.new(self.key, AES.MODE_GCM)
            self.nonce = cipher.nonce
            ciphertext = cipher.encrypt(plaintext.encode('utf8'))
            self.end_time = time.time()
            print(ciphertext)
            return ciphertext
        else:
            print("Invalid mode")
            return None

    def decrypt(self, ciphertext, mode):
        if mode == "ECB":
            # Medir el tiempo que tarda en descifrar
            self.start_time = time.time()
            cipher = AES.new(self.key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf8')
            self.end_time = time.time()
            print(plaintext)
            return plaintext
        elif mode == "GCM":
            # Medir el tiempo que tarda en descifrar
            self.start_time = time.time()
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
            plaintext = cipher.decrypt(ciphertext).decode('utf8')
            self.end_time = time.time()
            print(plaintext)
            return plaintext
        else:
            print("Invalid mode")
            return None

class RSAOAEP:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.private_key = self.key
        self.start_time = None
        self.end_time = None

    def encrypt(self, plaintext):
        # Medir el tiempo que tarda en cifrar
        data = plaintext.encode()

        # Dividir los datos en bloques de 214 bytes
        block_size = 214
        data_blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

        cipher_rsa = PKCS1_OAEP.new(self.public_key)

        self.start_time = time.time()
        # Cifrar cada bloque de datos con RSA-OAEP
        encrypted_blocks = [cipher_rsa.encrypt(block) for block in data_blocks]
        self.end_time = time.time()
        print(encrypted_blocks)

        return encrypted_blocks

    def decrypt(self, ciphertext):

        # Dividir los datos en bloques de 214 bytes
        block_size = 214

        # Inicializar un objeto PKCS1_OAEP con la clave privada
        cipher_rsa = PKCS1_OAEP.new(self.private_key)

        self.start_time = time.time()
        # Descifrar cada bloque de datos con RSA-OAEP
        decrypted_blocks = [cipher_rsa.decrypt(block) for block in ciphertext]
        self.end_time = time.time()

        # Unir los bloques de datos descifrados
        decrypted_data = b''.join(decrypted_blocks)

        # Convertir los datos descifrados de bytes a cadena
        plain_text = decrypted_data.decode()
        print(plain_text)

        return plain_text