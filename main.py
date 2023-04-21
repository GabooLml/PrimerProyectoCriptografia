from ciphers import *
from hashes import *
from signatures import *

plaintext = "Me llamo Gabriel Rojas Mendez"
totaltime = 0

def pruebas_cifrado():
    ## ChaCha 20
    cipherChacha20 = chacha20()
    result = cipherChacha20.encrypt(plaintext)
    total_time = cipherChacha20.end_time - cipherChacha20.start_time
    print(f"Tiempo total de cifrado ChaCha20: {total_time:.5f} segundos")

    ## AES256-ECB
    mode1 = "ECB"
    aes = AES256()
    ciphertext = aes.encrypt(plaintext, mode1)
    total_time = aes.end_time - aes.start_time
    print(f"Tiempo total de cifrado AES256-ECB: {total_time:.5f} segundos")

    ## AES256-GCM
    mode2 = "GCM"
    aes = AES256()
    ciphertext = aes.encrypt(plaintext, mode2)
    total_time = aes.end_time - aes.start_time
    print(f"Tiempo total de cifrado AES256-GCM: {total_time:.5f} segundos")

    ## RSA-OAEP 2048
    rsa = RSAOAEP()
    ciphertext = rsa.encrypt(plaintext)
    total_time = rsa.end_time - rsa.start_time
    print(f"Tiempo total de cifrado RSA-OAEP 2048 bits: {total_time:.5f} segundos")

def pruebas_descifrado():
    ## ChaCha 20
    cipherChacha20 = chacha20()
    result = cipherChacha20.encrypt(plaintext)
    cipherChacha20.decrypt(result)
    total_time = cipherChacha20.end_time - cipherChacha20.start_time
    print(f"Tiempo total de descifrado ChaCha20: {total_time:.5f} segundos")

    ## AES256-ECB
    mode1 = "ECB"
    aes = AES256()
    ciphertext = aes.encrypt(plaintext, mode1)
    aes.decrypt(ciphertext, mode1)
    total_time = aes.end_time - aes.start_time
    print(f"Tiempo total de descifrado AES256-ECB: {total_time:.5f} segundos")

    ## AES256-GCM
    mode2 = "GCM"
    aes = AES256()
    ciphertext = aes.encrypt(plaintext, mode2)
    aes.decrypt(ciphertext, mode2)
    total_time = aes.end_time - aes.start_time
    print(f"Tiempo total de descifrado AES256-GCM: {total_time:.5f} segundos")

    ## RSA-OAEP 2048
    rsa = RSAOAEP()
    ciphertext = rsa.encrypt(plaintext)
    rsa.decrypt(ciphertext)
    total_time = rsa.end_time - rsa.start_time
    print(f"Tiempo total de descifrado RSA-OAEP 2048 bits: {total_time:.5f} segundos")

def pruebas_hash():
    ## SHA-2 512 bits
    sha2 = SHA2()
    sha2.get_value_hash(plaintext)
    total_time = sha2.end_time - sha2.start_time
    print(f"Tiempo total de operación hash de SHA-2 512 bits: {total_time:.5f} segundos")

    ## SHA-3 512 bits
    sha3 = SHA3()
    sha3.get_value_hash(plaintext)
    total_time = sha3.end_time - sha3.start_time
    print(f"Tiempo total de operación hash de SHA-3 512 bits: {total_time:.5f} segundos")

    ## Scrypt 32 bits
    scryptV = Scrypt()
    scryptV.get_key(plaintext)
    total_time = scryptV.end_time - scryptV.start_time
    print(f"Tiempo total de operación hash de Scrypt 32 bits: {total_time:.5f} segundos")

def pruebas_firma():
    ## RSA-PSS
    rsa = RSAPSS()
    signature = rsa.sign_message(plaintext)
    total_time = rsa.end_time - rsa.start_time
    print(f"Tiempo total de firmado de RSA-PSS 2048 bits: {total_time:.5f} segundos")

    ## ECDSA 521 bits
    ecc1 = ECDSA()
    signature = ecc1.sign_message(plaintext)
    total_time = ecc1.end_time - ecc1.start_time
    print(f"Tiempo total de firmado de ECDSA 521 bits: {total_time:.5f} segundos")

    ## EdDSA 32 bits
    ecc2 = EdDSA()
    signature = ecc2.sign_message(plaintext)
    total_time = ecc2.end_time - ecc2.start_time
    print(f"Tiempo total de firmado de EdDSA 32 bits: {total_time:.5f} segundos")
    ecc2.verify_message(plaintext, signature)

def pruebas_verificacion():
    ## RSA-PSS
    rsa = RSAPSS()
    signature = rsa.sign_message(plaintext)
    rsa.verify_message(plaintext, signature)
    total_time = rsa.end_time - rsa.start_time
    print(f"Tiempo total de verificación de RSA-PSS 2048 bits: {total_time:.5f} segundos")

    ## ECDSA 521 bits
    ecc1 = ECDSA()
    signature = ecc1.sign_message(plaintext)
    ecc1.verify_message(plaintext, signature)
    total_time = ecc1.end_time - ecc1.start_time
    print(f"Tiempo total de verificación de ECDSA 521 bits: {total_time:.5f} segundos")

    ## EdDSA 32 bits
    ecc2 = EdDSA()
    signature = ecc2.sign_message(plaintext)
    ecc2.verify_message(plaintext, signature)
    total_time = ecc2.end_time - ecc2.start_time
    print(f"Tiempo total de verificación de EdDSA 32 bits: {total_time:.5f} segundos")

def main():
    while True:
        print("""\nSelecciona una opción del menú:
        1. Ejecutar las pruebas de cifrado
        2. Ejecutar las pruebas de descifrado
        3. Ejecutar las pruebas de hashing
        4. Ejecutar las pruebas de firmas
        5. Ejecutar las pruebas de verificación
        6. Salir""")

        opcion = input("Opción seleccionada: ")
        
        # Realiza una acción en función de la opción seleccionada
        if opcion == "1":
            print("Ha seleccionado la opción 1")
            pruebas_cifrado()
        elif opcion == "2":
            print("Ha seleccionado la opción 2")
            pruebas_descifrado()
        elif opcion == "3":
            print("Ha seleccionado la opción 3")
            pruebas_hash()
        elif opcion == "4":
            print("Ha seleccionado la opción 4")
            pruebas_firma()
        elif opcion == "5":
            print("Ha seleccionado la opción 5")
            pruebas_verificacion()
        elif opcion == "6":
            print("Saliendo del programa...")
            break  # Sale del bucle while
        else:
            print("Opción inválida. Por favor, seleccione una opción válida.") 

main()