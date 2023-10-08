import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def verificar_firma(documento, firma, public_key_path):
    with open(documento, "rb") as file:
        data = file.read()

    with open(public_key_path, "rb") as public_key_file:
        public_key = RSA.import_key(public_key_file.read())

    hash_obj = SHA256.new(data)

    try:
        pkcs1_15.new(public_key).verify(hash_obj, firma)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    documento_verificar = "documento.txt"
    firma_a_verificar = "firma.bin"
    public_key_path = "public_key.pem"

    if not os.path.exists(documento_verificar) or not os.path.exists(public_key_path):
        print("El archivo del documento o la clave pública no existen.")
    else:
        resultado = verificar_firma(documento_verificar, firma_a_verificar, public_key_path)
        if resultado:
            print("La firma es válida.")
        else:
            print("La firma no es válida.")

