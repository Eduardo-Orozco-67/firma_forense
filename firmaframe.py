import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from tkinter import Tk, Button, filedialog, messagebox, Label, Frame

clave_privada_pem = None
clave_publica_pem = None


def generar_par_de_claves():
    """
    Genera un par de claves pública y privada RSA de 2048 bits y las guarda en archivos.
    """
    global clave_privada_pem, clave_publica_pem

    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    clave_privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    clave_publica = clave_privada.public_key()
    clave_publica_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('clave_privada.pem', 'wb') as archivo_clave_privada:
        archivo_clave_privada.write(clave_privada_pem)
    with open('clave_publica.pem', 'wb') as archivo_clave_publica:
        archivo_clave_publica.write(clave_publica_pem)

    messagebox.showinfo("Claves Generadas", "Clave pública y privada generadas exitosamente.")


def firmar_archivo(clave_privada_pem, ruta_archivo):
    """
    Firma un archivo utilizando la clave privada y guarda la firma en un archivo con extensión .sig.
    """
    with open(ruta_archivo, 'rb') as archivo:
        datos = archivo.read()

    clave_privada = serialization.load_pem_private_key(clave_privada_pem, password=None)

    firma = clave_privada.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(ruta_archivo + '.sig', 'wb') as archivo_firma:
        archivo_firma.write(firma)

    print("Archivo firmado:", ruta_archivo)


def verificar_firma(clave_publica_pem, ruta_archivo, ruta_firma):
    """
    Verifica si la firma de un archivo es válida utilizando la clave pública.
    """
    with open(ruta_archivo, 'rb') as archivo:
        datos = archivo.read()

    with open(ruta_firma, 'rb') as archivo_firma:
        firma = archivo_firma.read()

    clave_publica = serialization.load_pem_public_key(clave_publica_pem)

    try:
        clave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # La firma es válida
    except InvalidSignature:
        return False  # La firma no es válida


def seleccionar_archivo():
    """
    Abre una ventana de selección de archivos y devuelve la ruta del archivo seleccionado.
    """
    ruta_archivo = filedialog.askopenfilename()
    if ruta_archivo:
        return ruta_archivo
    else:
        return None


def firmar_archivo_seleccionado():
    """
    Función de acción para firmar un archivo seleccionado por el usuario.
    """
    ruta_archivo = seleccionar_archivo()
    if ruta_archivo:
        firmar_archivo(clave_privada_pem, ruta_archivo)
        messagebox.showinfo("Archivo Firmado", "Archivo firmado exitosamente.")


def verificar_firma_seleccionada():
    """
    Función de acción para verificar la firma de un archivo seleccionado por el usuario.
    """
    ruta_archivo = seleccionar_archivo()
    if ruta_archivo:
        ruta_firma = filedialog.askopenfilename()
        if ruta_firma:
            if verificar_firma(clave_publica_pem, ruta_archivo, ruta_firma):
                messagebox.showinfo("Verificación de Firma", "La firma es válida.")
            else:
                messagebox.showerror("Verificación de Firma", "La firma no es válida.")
        else:
            messagebox.showerror("Verificación de Firma", "Por favor, selecciona un archivo de firma.")


# Resto del código para la interfaz de usuario...

# Crear ventana principal
root = Tk()
root.title("Firma Digital")
root.geometry("400x400")  # Tamaño de la ventana 400x400

# Crear un frame para organizar los botones y las instrucciones
frame = Frame(root)
frame.pack(padx=20, pady=20)  # Espacio alrededor del frame

# Instrucciones de uso del programa - Parte 1
instructions_label1 = Label(frame, text="Instrucciones de uso:", justify="left")
instructions_label1.pack()

instructions_part1 = Label(frame, text="1. Genera un par de claves haciendo clic en 'Generar Claves'.", justify="left")
instructions_part1.pack()

instructions_part2 = Label(frame, text="2. Firma un archivo seleccionando 'Firmar Archivo'.", justify="left")
instructions_part2.pack()

# Instrucciones de uso del programa - Parte 2
instructions_label2 = Label(frame, text="3. Verifica una firma seleccionando 'Verificar Firma'.", justify="left")
instructions_label2.pack()

instructions_part3 = Label(frame, text="Para verificar una firma:", justify="left")
instructions_part3.pack()

instructions_part4 = Label(frame, text="- Selecciona el archivo que deseas verificar y haz clic en 'Abrir'. \n - Luego, se abrirá otra ventana de selección de archivos. \n - Selecciona el archivo de firma del documento que deseas verificar \n (debe tener la extensión .sig) y haz clic en 'Abrir'.", justify="left")
instructions_part4.pack()

# Botones
generate_keys_button = Button(frame, text="Generar Claves", command=generar_par_de_claves, width=20, height=2)
sign_button = Button(frame, text="Firmar Archivo", command=firmar_archivo_seleccionado, width=20, height=2)
verify_button = Button(frame, text="Verificar Firma", command=verificar_firma_seleccionada, width=20, height=2)

generate_keys_button.pack(pady=10)
sign_button.pack(pady=10)
verify_button.pack(pady=10)

root.mainloop()
