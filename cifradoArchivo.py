from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Clave y vector de inicialización (IV)
clave = get_random_bytes(16)
iv = get_random_bytes(16)

# Función para cifrar archivo de texto con AES y CBC
def cifrar_archivo(ruta_archivo, ruta_archivo_cifrado):
    with open(ruta_archivo, 'rb') as f:
        contenido = f.read()
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    contenido_cifrado = cipher.encrypt(pad(contenido, AES.block_size))
    print(contenido_cifrado)
    with open(ruta_archivo_cifrado, 'wb') as f:
        f.write(contenido_cifrado)

# Función para descifrar archivo de texto cifrado con AES y CBC
def descifrar_archivo(ruta_archivo_cifrado, ruta_archivo_descifrado):
    with open(ruta_archivo_cifrado, 'rb') as f:
        contenido_cifrado = f.read()
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    contenido_descifrado = unpad(cipher.decrypt(contenido_cifrado), AES.block_size)
    with open(ruta_archivo_descifrado, 'wb') as f:
        f.write(contenido_descifrado)

# Ejemplo de uso
ruta_archivo = 'C:/Users/Bryan/Desktop/texto.txt'
ruta_archivo_cifrado = 'C:/Users/Bryan/Desktop/textoCifrado.txt'
ruta_archivo_descifrado = 'C:/Users/Bryan/Desktop/textoDescifrado.txt'

# Cifrado
cifrar_archivo(ruta_archivo, ruta_archivo_cifrado)

# Descifrado
descifrar_archivo(ruta_archivo_cifrado, ruta_archivo_descifrado)
