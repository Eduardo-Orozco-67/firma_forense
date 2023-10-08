import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def firmar_documento(documento, firma_output, private_key_path):
    with open(documento, "rb") as file:
        data = file.read()

    with open(private_key_path, "rb") as private_key_file:
        private_key = RSA.import_key(private_key_file.read())

    hash_obj = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash_obj)

    with open(firma_output, "wb") as firma_file:
        firma_file.write(signature)

if __name__ == "__main__":
    documento_a_firmar = "documento.txt"
    firma_output = "firma.bin"
    private_key_path = "private_key.pem"

    if not os.path.exists(documento_a_firmar) or not os.path.exists(private_key_path):
        print("El archivo del documento o la clave privada no existen.")
    else:
        firmar_documento(documento_a_firmar, firma_output, private_key_path)
        print("Firma agregada al documento:", firma_output)
