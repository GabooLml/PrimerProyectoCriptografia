import matplotlib.pyplot as plt
import numpy as np
import random
from ciphers import *
from hashes import *
from signatures import *
2
vectores = ['Gabriel Rojas Mendez Teresita de Jesus Duran Lopez Alejandro Jesus Antonio Roblero','Universidad Nacional Autonoma de Mexico','Facultad de Ingenieria', "El Antonio se va al MIT"]

executes = list(range(1,6))
time_list_1 = []
time_list_2 = []
time_list_3 = []
time_list_4 = []


def pruebas_cifrado():
    ## Inicialización de arreglos
    time_list_1.clear()
    time_list_2.clear()
    time_list_3.clear()
    time_list_4.clear()

    ## ChaCha 20
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        cipherChacha20 = chacha20()
        print("=============== ChaCha ==========================")
        print(vector)
        result = cipherChacha20.encrypt(vector)
        total_time = cipherChacha20.end_time - cipherChacha20.start_time
        time_list_1.append(total_time)

    ## AES256-ECB
    mode1 = "ECB"   
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        aes = AES256()
        print("================ AES-256 ECB =========================")
        print(vector)
        ciphertext = aes.encrypt(vector, mode1)
        total_time = aes.end_time - aes.start_time
        time_list_2.append(total_time)
    
    ## AES256-GCM
    mode2 = "GCM"
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        aes = AES256()
        print("================ AES-256 GCM =========================")
        print(vector)
        ciphertext = aes.encrypt(vector, mode2)
        total_time = aes.end_time - aes.start_time
        time_list_3.append(total_time)
    
    ## RSA-OAEP 2048
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        rsa = RSAOAEP()
        print("================ RSA-OAEP 2048 =========================")
        print(vector)
        ciphertext = rsa.encrypt(vector)
        total_time = rsa.end_time - rsa.start_time
        time_list_4.append(total_time)
    
def pruebas_descifrado():
    ## Inicialización de arreglos
    time_list_1.clear()
    time_list_2.clear()
    time_list_3.clear()
    time_list_4.clear()

    ## ChaCha 20
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        cipherChacha20 = chacha20()
        print("=============== ChaCha ==========================")
        print(vector)
        result = cipherChacha20.encrypt(vector)
        cipherChacha20.decrypt(result)
        total_time = cipherChacha20.end_time - cipherChacha20.start_time
        time_list_1.append(total_time)
    
    ## AES256-ECB
    mode1 = "ECB"
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        aes = AES256()
        print("=============== AES-256 ECB ==========================")
        print(vector)
        ciphertext = aes.encrypt(vector, mode1)
        aes.decrypt(ciphertext, mode1)
        total_time = aes.end_time - aes.start_time
        time_list_2.append(total_time)
    
    ## AES256-GCM
    mode2 = "GCM"
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        aes = AES256()
        print("=============== AES-256 GCM ==========================")
        print(vector)
        ciphertext = aes.encrypt(vector, mode2)
        aes.decrypt(ciphertext, mode2)
        total_time = aes.end_time - aes.start_time
        time_list_3.append(total_time)
    
    ## RSA-OAEP 2048
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        rsa = RSAOAEP()
        print("============== RSA-OAEP 2048 ===========================")
        print(vector)
        ciphertext = rsa.encrypt(vector)
        rsa.decrypt(ciphertext)
        total_time = rsa.end_time - rsa.start_time
        time_list_4.append(total_time)
    
def pruebas_hash():
    ## Inicialización de arreglos
    time_list_1.clear()
    time_list_2.clear()
    time_list_3.clear()

    ## SHA-2 512 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        sha2 = SHA2()
        print("============== SHA-2 512 BITS ===========================")
        print(vector)
        sha2.get_value_hash(vector)
        total_time = sha2.end_time - sha2.start_time
        time_list_1.append(total_time)
    
    ## SHA-3 512 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        sha3 = SHA3()
        print("============== SHA-3 512 BITS ===========================")
        print(vector)
        sha3.get_value_hash(vector)
        total_time = sha3.end_time - sha3.start_time
        time_list_2.append(total_time)

    ## Scrypt 32 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        scryptV = Scrypt()
        print("============= Scrypt 32 BITS ============================")
        print(vector)
        scryptV.get_key(vector)
        total_time = scryptV.end_time - scryptV.start_time
        time_list_3.append(total_time)

def pruebas_firma():
    ## Inicialización de arreglos
    time_list_1.clear()
    time_list_2.clear()
    time_list_3.clear()

    ## RSA-PSS
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        rsa = RSAPSS()
        print("============ RSA-PSS =============================")
        print(vector)
        signature = rsa.sign_message(vector)
        total_time = rsa.end_time - rsa.start_time
        time_list_1.append(total_time)

    ## ECDSA 521 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        ecc1 = ECDSA()
        print("============ ECDSA =============================")
        print(vector)
        signature = ecc1.sign_message(vector)
        total_time = ecc1.end_time - ecc1.start_time
        time_list_2.append(total_time)

    ## EdDSA 32 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        ecc2 = EdDSA()
        print("============ EdDSA =============================")
        print(vector)
        signature = ecc2.sign_message(vector)
        total_time = ecc2.end_time - ecc2.start_time
        time_list_3.append(total_time)

def pruebas_verificacion():
    ## Inicialización de arreglos
    time_list_1.clear()
    time_list_2.clear()
    time_list_3.clear()

    ## RSA-PSS
    for i in range(len(executes)):
        rsa = RSAPSS()
        vector = vectores[random.randint(0, 3)]
        print("============ RSA-PSS =============================")
        print(vector)
        signature = rsa.sign_message(vector)
        rsa.verify_message(vector, signature)
        total_time = rsa.end_time - rsa.start_time
        time_list_1.append(total_time)

    ## ECDSA 521 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        ecc1 = ECDSA()
        print("=========================================")
        print(vector)
        signature = ecc1.sign_message(vector)
        ecc1.verify_message(vector, signature)
        total_time = ecc1.end_time - ecc1.start_time
        time_list_2.append(total_time)

    ## EdDSA 32 bits
    for i in range(len(executes)):
        vector = vectores[random.randint(0, 3)]
        ecc2 = EdDSA()
        print("=========================================")
        print(vector)
        signature = ecc2.sign_message(vector)
        ecc2.verify_message(vector, signature)
        total_time = ecc2.end_time - ecc2.start_time
        time_list_3.append(total_time)

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
            plt.plot(executes, time_list_1, ':', label='ChaCha20')
            plt.plot(executes, time_list_2, label='AES ECB')
            plt.plot(executes, time_list_3, '--', label='AES GCM')
            plt.plot(executes, time_list_4, label='RCA-OAEP')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Cifrado')
            plt.legend()
            plt.show()

        elif opcion == "2":
            print("Ha seleccionado la opción 2")
            pruebas_descifrado()
            plt.grid()
            plt.plot(executes, time_list_1, label='ChaCha20')
            plt.plot(executes, time_list_2, label='AES ECB')
            plt.plot(executes, time_list_3, label='AES GCM')
            plt.plot(executes, time_list_4, label='RCA-OAEP')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Descifrado')
            plt.legend()
            plt.show()

        elif opcion == "3":
            print("Ha seleccionado la opción 3")
            pruebas_hash()
            plt.grid()
            plt.plot(executes, time_list_1, label='SHA-2')
            plt.plot(executes, time_list_2, label='SHA-3')
            plt.plot(executes, time_list_3, label='Scrypt')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Hashing')
            plt.legend()
            plt.show()

        elif opcion == "4":
            print("Ha seleccionado la opción 4")
            pruebas_firma()
            plt.grid()
            plt.plot(executes, time_list_1, label='RSA-PSS')
            plt.plot(executes, time_list_2, label='ECDSA')
            plt.plot(executes, time_list_3, label='EdDSA')
            plt.xlabel('Ejecuciones')
            plt.ylabel('Tiempo')
            plt.title('Firmas')
            plt.legend()
            plt.show()

        elif opcion == "5":
            print("Ha seleccionado la opción 5")
            pruebas_verificacion()
            plt.grid()
            plt.plot(executes, time_list_1, label='RSA-PSS')
            plt.plot(executes, time_list_2, label='ECDSA')
            plt.plot(executes, time_list_3, label='EdDSA')
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