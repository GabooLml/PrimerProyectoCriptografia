import time
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS, eddsa

class RSAPSS:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.start_time = None
        self.end_time = None

    def sign_message(self, message):
        # Medir el tiempo que tarda en firmar el mensaje
        self.start_time = time.time()
        h = SHA512.new(message.encode("utf-8"))
        signature = pkcs1_15.new(self.key).sign(h)
        self.end_time = time.time()
        return signature

    def verify_message(self, message, signature):
        # Medir el tiempo que tarda en verificar el mensaje
        self.start_time = time.time()
        h = SHA512.new(message.encode("utf-8"))
        public_key = self.key.publickey()
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            print("Signature is valid.")
        except (ValueError, TypeError):
            print("Signature is not valid.")
        self.end_time = time.time()

class ECDSA:
    def __init__(self):
        self.key = ECC.generate(curve='P-521')
        self.start_time = None
        self.end_time = None

    def sign_message(self, message):
        # Medir el tiempo que tarda en firmar el mensaje
        self.start_time = time.time()
        h = SHA512.new(message.encode('utf-8'))
        signature = DSS.new(self.key, 'fips-186-3').sign(h)
        self.end_time = time.time()
        return signature
    
    def verify_message(self, message, signature):
        # Medir el tiempo que tarda en verificar el mensaje
        self.start_time = time.time()
        h = SHA512.new(message.encode('utf-8'))
        public_key = self.key.public_key()
        try:
            DSS.new(public_key, 'fips-186-3').verify(h, signature)
            print("Signature is valid.")
        except (ValueError, TypeError):
            print("Signature is not valid.")
        self.end_time = time.time()

class EdDSA:
    def __init__(self):
        self.key = ECC.generate(curve='Ed25519')
        self.start_time = None
        self.end_time = None

    def sign_message(self, message):
        # Medir el tiempo que tarda en firmar el mensaje
        self.start_time = time.time()
        h = SHA512.new(message.encode('utf-8'))
        signature = eddsa.new(self.key,'rfc8032').sign(h)
        self.end_time = time.time()
        return signature

    def verify_message(self, message, signature):
        # Medir el tiempo que tarda en verificar el mensaje
        self.start_time = time.time()
        h = SHA512.new(message.encode('utf-8'))
        public_key = self.key.public_key()
        try:
            eddsa.new(public_key,'rfc8032').verify(h, signature)
            print("Signature is valid.")
        except (ValueError, TypeError):
            print("Signature is not valid.")
        self.end_time = time.time()