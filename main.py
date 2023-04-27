import matplotlib.pyplot as plt
import numpy as np
import random
from ciphers import *
from hashes import *
from signatures import *

plaintext = "Gabriel Rojas Mendez Teresita de Jesus Duran Lopez Alejandro Jesus Antonio Roblero"
plaintext2 = "Universidad Nacional Autonoma de Mexico"
plaintext3 = "Facultad de Ingenieria"
plaintext4 = 'a'*1000

vectores = [plaintext, plaintext2, plaintext3, plaintext4]

executes = list(range(1,101))
ChaCha_list = []
AES_ECB_list = []
AES_GCM_list = []
RSA_OAEP_list = []


def pruebas_cifrado():
    ## Inicialización de arreglos
    ChaCha_list.clear()
    AES_ECB_list.clear()
    AES_GCM_list.clear()
    RSA_OAEP_list.clear()

    ## ChaCha 20
    for i in range(len(executes)):
        cipherChacha20 = chacha20()
        result = cipherChacha20.encrypt(vectores[random.randint(0, 3)])
        total_time = cipherChacha20.end_time - cipherChacha20.start_time
        ChaCha_list.append(total_time)

    ## AES256-ECB
    mode1 = "ECB"   
    for i in range(len(executes)):
        aes = AES256()
        ciphertext = aes.encrypt(vectores[random.randint(0, 3)], mode1)
        total_time = aes.end_time - aes.start_time
        AES_ECB_list.append(total_time)
    
    ## AES256-GCM
    mode2 = "GCM"
    for i in range(len(executes)):
        aes = AES256()
        ciphertext = aes.encrypt(vectores[random.randint(0, 3)], mode2)
        total_time = aes.end_time - aes.start_time
        AES_GCM_list.append(total_time)
    
    ## RSA-OAEP 2048
    for i in range(len(executes)):
        rsa = RSAOAEP()
        ciphertext = rsa.encrypt(vectores[random.randint(0, 3)])
        total_time = rsa.end_time - rsa.start_time
        RSA_OAEP_list.append(total_time)
    
def pruebas_descifrado():
    ## Inicialización de arreglos
    ChaCha_list.clear()
    AES_ECB_list.clear()
    AES_GCM_list.clear()
    RSA_OAEP_list.clear()

    ## ChaCha 20
    for i in range(len(executes)):
        cipherChacha20 = chacha20()
        result = cipherChacha20.encrypt(vectores[random.randint(0, 3)])
        cipherChacha20.decrypt(result)
        total_time = cipherChacha20.end_time - cipherChacha20.start_time
        ChaCha_list.append(total_time)
    
    ## AES256-ECB
    mode1 = "ECB"
    for i in range(len(executes)):
        aes = AES256()
        ciphertext = aes.encrypt(vectores[random.randint(0, 3)], mode1)
        aes.decrypt(ciphertext, mode1)
        total_time = aes.end_time - aes.start_time
        AES_ECB_list.append(total_time)
    
    ## AES256-GCM
    mode2 = "GCM"
    for i in range(len(executes)):
        aes = AES256()
        ciphertext = aes.encrypt(vectores[random.randint(0, 3)], mode2)
        aes.decrypt(ciphertext, mode2)
        total_time = aes.end_time - aes.start_time
        AES_GCM_list.append(total_time)
    
    ## RSA-OAEP 2048
    rsa = RSAOAEP()
    for i in range(len(executes)):
        ciphertext = rsa.encrypt(vectores[random.randint(0, 3)])
        rsa.decrypt(ciphertext)
        total_time = rsa.end_time - rsa.start_time
        RSA_OAEP_list.append(total_time)
    
def pruebas_hash():
    ## Inicialización de arreglos
    ChaCha_list.clear()
    AES_ECB_list.clear()
    AES_GCM_list.clear()

    ## SHA-2 512 bits
    for i in range(len(executes)):
        sha2 = SHA2()
        sha2.get_value_hash(vectores[random.randint(0, 3)])
        total_time = sha2.end_time - sha2.start_time
        ChaCha_list.append(total_time)
    
    ## SHA-3 512 bits
    for i in range(len(executes)):
        sha3 = SHA3()
        sha3.get_value_hash(vectores[random.randint(0, 3)])
        total_time = sha3.end_time - sha3.start_time
        AES_ECB_list.append(total_time)

    ## Scrypt 32 bits
    for i in range(len(executes)):
        scryptV = Scrypt()
        scryptV.get_key(vectores[random.randint(0, 3)])
        total_time = scryptV.end_time - scryptV.start_time
        AES_GCM_list.append(total_time)

def pruebas_firma():
    ## Inicialización de arreglos
    ChaCha_list.clear()
    AES_ECB_list.clear()
    AES_GCM_list.clear()

    ## RSA-PSS
    for i in range(len(executes)):
        rsa = RSAPSS()
        signature = rsa.sign_message(vectores[random.randint(0, 3)])
        total_time = rsa.end_time - rsa.start_time
        ChaCha_list.append(total_time)

    ## ECDSA 521 bits
    for i in range(len(executes)):
        ecc1 = ECDSA()
        signature = ecc1.sign_message(vectores[random.randint(0, 3)])
        total_time = ecc1.end_time - ecc1.start_time
        AES_ECB_list.append(total_time)

    ## EdDSA 32 bits
    for i in range(len(executes)):
        ecc2 = EdDSA()
        signature = ecc2.sign_message(vectores[random.randint(0, 3)])
        total_time = ecc2.end_time - ecc2.start_time
        AES_GCM_list.append(total_time)

def pruebas_verificacion():
    ## Inicialización de arreglos
    ChaCha_list.clear()
    AES_ECB_list.clear()
    AES_GCM_list.clear()

    ## RSA-PSS
    for i in range(len(executes)):
        rsa = RSAPSS()
        signature = rsa.sign_message(vectores[random.randint(0, 3)])
        rsa.verify_message(plaintext, signature)
        total_time = rsa.end_time - rsa.start_time
        ChaCha_list.append(total_time)

    ## ECDSA 521 bits
    for i in range(len(executes)):
        ecc1 = ECDSA()
        signature = ecc1.sign_message(vectores[random.randint(0, 3)])
        ecc1.verify_message(plaintext, signature)
        total_time = ecc1.end_time - ecc1.start_time
        AES_ECB_list.append(total_time)

    ## EdDSA 32 bits
    for i in range(len(executes)):
        ecc2 = EdDSA()
        signature = ecc2.sign_message(vectores[random.randint(0, 3)])
        ecc2.verify_message(plaintext, signature)
        total_time = ecc2.end_time - ecc2.start_time
        AES_GCM_list.append(total_time)

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
            plt.grid()
            plt.plot(executes, ChaCha_list, ':', label='ChaCha20')
            plt.plot(executes, AES_ECB_list, label='AES ECB')
            plt.plot(executes, AES_GCM_list, '--', label='AES GCM')
            plt.plot(executes, RSA_OAEP_list, label='RCA-OAEP')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Cifrado')
            plt.legend()
            plt.show()

        elif opcion == "2":
            print("Ha seleccionado la opción 2")
            pruebas_descifrado()
            plt.grid()
            plt.plot(executes, ChaCha_list, label='ChaCha20')
            plt.plot(executes, AES_ECB_list, label='AES ECB')
            plt.plot(executes, AES_GCM_list, label='AES GCM')
            plt.plot(executes, RSA_OAEP_list, label='RCA-OAEP')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Descifrado')
            plt.legend()
            plt.show()

        elif opcion == "3":
            print("Ha seleccionado la opción 3")
            pruebas_hash()
            plt.grid()
            plt.plot(executes, ChaCha_list, label='SHA-2')
            plt.plot(executes, AES_ECB_list, label='SHA-3')
            plt.plot(executes, AES_GCM_list, label='Scrypt')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Hashing')
            plt.legend()
            plt.show()

        elif opcion == "4":
            print("Ha seleccionado la opción 4")
            pruebas_firma()
            plt.grid()
            plt.plot(executes, ChaCha_list, label='RSA-PSS')
            plt.plot(executes, AES_ECB_list, label='ECDSA')
            plt.plot(executes, AES_GCM_list, label='EdDSA')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Firmas')
            plt.legend()
            plt.show()

        elif opcion == "5":
            print("Ha seleccionado la opción 5")
            pruebas_verificacion()
            plt.grid()
            plt.plot(executes, ChaCha_list, label='RSA-PSS')
            plt.plot(executes, AES_ECB_list, label='ECDSA')
            plt.plot(executes, AES_GCM_list, label='EdDSA')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Verificaciones')
            plt.legend()
            plt.show()

        elif opcion == "6":
            print("Saliendo del programa...")
            break  # Sale del bucle while
        else:
            print("Opción inválida. Por favor, seleccione una opción válida.") 

main()