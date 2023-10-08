# Firma Digital en Python

Este es un proyecto de ejemplo que te permite generar claves RSA, firmar archivos y verificar firmas utilizando Python y la biblioteca cryptography.

## Instrucciones de Uso

1. **Generar Claves:**
   - Haz clic en el botón "Generar Claves" para generar un par de claves pública y privada RSA de 2048 bits.
   - Las claves se guardarán en los archivos `private_key.pem` y `public_key.pem` en el directorio del proyecto.

2. **Firmar Archivo:**
   - Selecciona un archivo (PDF, TXT o DOCX) que deseas firmar haciendo clic en "Firmar Archivo".
   - La aplicación firmará el archivo utilizando la clave privada y guardará la firma en un archivo con la extensión `.sig` en el mismo directorio del archivo original.

3. **Verificar Firma:**
   - Para verificar la firma de un archivo, selecciona primero el archivo original que deseas verificar y haz clic en "Abrir".
   - Luego, selecciona el archivo de firma correspondiente (con extensión `.sig`) y haz clic en "Abrir".
   - La aplicación verificará si la firma es válida y te mostrará un mensaje de confirmación o error.

## Requisitos

Asegúrate de tener Python 3.x instalado en tu computadora. Además, instala las siguientes bibliotecas Python utilizando pip:

```bash
pip install cryptography
