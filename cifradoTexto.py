import tkinter as tk
import tkinter.messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os


class data():
    vartexto = b''
    clave = os.urandom(16)
    iv = os.urandom(16)


datos = data()

root = tk.Tk()

root.title("Cifrado Texto Plano AES")
root.geometry("400x325")

# Define una etiqueta para el texto a cifrar
texto_original_label = tk.Label(root, text="Texto a cifrar:")
texto_original_label.pack()

# Define una entrada de texto para el texto a cifrar
texto_original_entry = tk.Entry(root, width=50)
texto_original_entry.pack()

# Define una etiqueta para mostrar la clave de cifrado
clave_random_label = tk.Label(root, text="Clave de cifrado generada aleatoriamente:")
clave_random_label.pack()

# Define una entrada de texto para mostrar la clave de cifrado
clave_random_entry = tk.Entry(root, state="readonly", width=50)
clave_random_entry.pack()

# Define una etiqueta para mostrar el texto cifrado
texto_cifrado_label = tk.Label(root, text="El texto cifrado es:")
texto_cifrado_label.pack()

# Define una entrada de texto para mostrar el texto cifrado
texto_original_cifrado_entry = tk.Entry(root, state="readonly", width=50)
texto_original_cifrado_entry.pack()

# Función para el botón de cifrado
def cifrar():
    # Obtiene el texto introducido por el usuario
    texto = texto_original_entry.get().encode()

    # Genera una clave de cifrado aleatoria de 16 bytes
    clavecif=datos.clave
    # Genera un vector de inicialización aleatorio
    ivcif = datos.iv

    # Crear un cifrador AES en modo CBC con el vector de inicialización especificado
    cipher = AES.new(clavecif, AES.MODE_CBC, ivcif)

    # Añadir padding al mensaje para que su longitud sea un múltiplo del tamaño del bloque
    padded_message = texto + ((AES.block_size - len(texto) % AES.block_size) * chr(AES.block_size - len(texto) % AES.block_size)).encode()

    # Cifrar el mensaje
    ciphertext = cipher.encrypt(padded_message)
    print(ciphertext)
    datos.vartexto = ciphertext

    # Muestra la clave de cifrado en la entrada de texto correspondiente
    clave_random_entry.configure(state="normal")
    clave_random_entry.delete(0, tk.END)
    clave_random_entry.insert(0, repr(clavecif))
    clave_random_entry.configure(state="readonly")

    # Muestra el texto cifrado en su respectivo entry
    texto_original_cifrado_entry.configure(state="normal")
    texto_original_cifrado_entry.delete(0, tk.END)
    texto_original_cifrado_entry.insert(0, repr(ciphertext))
    texto_original_cifrado_entry.configure(state="readonly")

# Define un botón para el cifrado
cifrar_button = tk.Button(root, text="Cifrar", command=cifrar)
cifrar_button.pack()

#--------------------------------------------------------

# Define una etiqueta para el texto cifrado
texto_cifrado_label = tk.Label(root, text="Texto cifrado:")
texto_cifrado_label.pack()

# Define una entrada de texto para el texto cifrado
texto_cifrado_entry = tk.Entry(root, width=50)
texto_cifrado_entry.pack()

# Define una etiqueta para la clave de cifrado
clave_label = tk.Label(root, text="Clave de cifrado:")
clave_label.pack()

# Define una entrada de texto para la clave de cifrado
clave_cifrada_entry = tk.Entry(root, width=50)
clave_cifrada_entry.pack()

# Define una etiqueta para el texto descifrado
texto_descifrado_label = tk.Label(root, text="El texto descifrado es:")
texto_descifrado_label.pack()

# Define una entrada de texto mostrar el texto descifrado
texto_descifrado_entry = tk.Entry(root, state="readonly", width=50)
texto_descifrado_entry.pack()

# Define una función para el botón de descifrado
def descifrar():
    # Obtiene el texto cifrado introducido por el usuario
    #texto_cifrado_original = bytes.fromhex(texto_cifrado_entry.get())
    texto_cifrado_original = datos.vartexto

    # Obtiene la clave de cifrado introducida por el usuario
    #clave = bytes.fromhex(clave_cifrada_entry.get())
    clavedes=datos.clave

    # Obtiene el vector de inicialización del texto cifrado
    #iv = texto_cifrado_original[:AES.block_size]
    ivdesc=datos.iv

   # Crear un descifrador AES en modo CBC con el vector de inicialización especificado
    cipher = AES.new(clavedes, AES.MODE_CBC, ivdesc)

    # Descifrar el mensaje
    plaintext = cipher.decrypt(texto_cifrado_original)

    # Eliminar el padding del mensaje descifrado
    unpadded_plaintext = plaintext[:-plaintext[-1]].decode()

    print(unpadded_plaintext)

    # Muestra el texto cifrado en su respectivo entry
    texto_descifrado_entry.configure(state="normal")
    texto_descifrado_entry.delete(0, tk.END)
    texto_descifrado_entry.insert(0, unpadded_plaintext)
    texto_descifrado_entry.configure(state="readonly")


# Define un botón para el descifrado
descifrar_button = tk.Button(root, text="Descifrar", command=descifrar)
descifrar_button.pack()

# Inicia el bucle de eventos
root.mainloop()
