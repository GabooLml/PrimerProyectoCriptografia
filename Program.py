from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import os

# Generar una clave y un nonce
key = os.urandom(32)
nonce = os.urandom(16)

# Crear el objeto Cipher
backend = default_backend()
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

# Medir el tiempo que tarda en cifrar 1MB de datos
start_time = time.time()

# Cifrar 1MB de datos
plaintext = b"Me llamo Gabriel Rojas Mendez" * 1000000
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

end_time = time.time()

# Calcular el tiempo total que tardó en cifrar 1MB de datos
total_time = end_time - start_time

print(f"Tiempo total: {total_time:.5f} segundos")
