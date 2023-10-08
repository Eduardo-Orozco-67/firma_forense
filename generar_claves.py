import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from tkinter import Tk, Button, filedialog, messagebox, Label, Frame

private_key_pem = None
public_key_pem = None

def generate_key_pair():
    global private_key_pem, public_key_pem

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_pem)
    with open('public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_pem)

    private_key_pem, public_key_pem = private_pem, public_pem
    messagebox.showinfo("Keys Generated", "Public and private keys generated successfully.")

def sign_file(private_key_pem, file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(file_path + '.sig', 'wb') as signature_file:
        signature_file.write(signature)

    print("File signed:", file_path)

def verify_signature(public_key_pem, file_path, signature_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    with open(signature_path, 'rb') as signature_file:
        signature = signature_file.read()

    public_key = serialization.load_pem_public_key(public_key_pem)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        return file_path
    else:
        return None

def sign_selected_file():
    file_path = select_file()
    if file_path:
        sign_file(private_key_pem, file_path)
        messagebox.showinfo("File Signed", "File signed successfully.")

def verify_selected_file():
    file_path = select_file()
    if file_path:
        signature_path = filedialog.askopenfilename()
        if signature_path:
            if verify_signature(public_key_pem, file_path, signature_path):
                messagebox.showinfo("Signature Verification", "Signature is valid.")
            else:
                messagebox.showerror("Signature Verification", "Signature is invalid.")
        else:
            messagebox.showerror("Signature Verification", "Please select a signature file.")

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

instructions_part1 = Label(frame, text="1. Genera claves haciendo clic en 'Generar Claves'.", justify="left")
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
generate_keys_button = Button(frame, text="Generar Claves", command=generate_key_pair, width=20, height=2)
sign_button = Button(frame, text="Firmar Archivo", command=sign_selected_file, width=20, height=2)
verify_button = Button(frame, text="Verificar Firma", command=verify_selected_file, width=20, height=2)

generate_keys_button.pack(pady=10)
sign_button.pack(pady=10)
verify_button.pack(pady=10)

root.mainloop()
