import hashlib
import Crypto.Util.number
import Crypto.Random
from PyPDF2 import PdfReader, PdfWriter

# Generar primos
def generar_primo(bits):
    return Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

# Función para generar claves RSA
def generar_claves(bits):
    p = generar_primo(bits)
    q = generar_primo(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = Crypto.Util.number.inverse(e, phi)
    return (n, e), (n, d)

# Función para hashear
def calcular_hash(mensaje):
    return int(hashlib.sha256(mensaje).hexdigest(), 16)

# Función para firmar digitalmente un mensaje utilizando la clave privada
def firmar(mensaje, clave_privada):
    n, d = clave_privada
    hash_mensaje = calcular_hash(mensaje)
    return pow(hash_mensaje, d, n)

# Función para verificar la firma digital utilizando la clave pública
def verificar(mensaje, firma, clave_publica):
    n, e = clave_publica
    hash_mensaje = calcular_hash(mensaje)
    hash_firma = pow(firma, e, n)
    return hash_firma == hash_mensaje

# Leer el contenido del archivo PDF
def leer_pdf(nombre_archivo):
    with open(nombre_archivo, 'rb') as file:
        reader = PdfReader(file)
        contenido = b""
        for page in reader.pages:
            contenido += page.extract_text().encode()
        return contenido

# Agregar la firma digital al archivo PDF
def agregar_firma_pdf(nombre_archivo, firma):
    with open(nombre_archivo, 'rb') as file:
        reader = PdfReader(file)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        metadata = {
            '/FirmaDigital': firma
        }
        writer.add_metadata(metadata)

        with open('documento_firmado.pdf', 'wb') as output_file:
            writer.write(output_file)

# Obtener la firma digital del PDF
def obtener_firma_pdf(nombre_archivo):
    with open(nombre_archivo, 'rb') as file:
        reader = PdfReader(file)
        metadata = reader.metadata
        return metadata.get('/FirmaDigital', None)

# Nombre del archivo PDF
archivo_pdf = 'NDA.pdf'

# Leer el PDF
contenido_pdf = leer_pdf(archivo_pdf)

# Generar claves RSA para Alice
clave_publica_alice, clave_privada_alice = generar_claves(1024)

# Firmar el PDF usando la clave privada de Alice
firma_alice = firmar(contenido_pdf, clave_privada_alice)

# Firmar PDF
agregar_firma_pdf(archivo_pdf, str(firma_alice))

# Obtener la firma del PDF
firma_obtenida = obtener_firma_pdf('documentofake.pdf')

# Verificar la firma digital utilizando la clave pública de Alice
verificacion = verificar(contenido_pdf, int(firma_obtenida), clave_publica_alice)

if verificacion:
    print("La firma digital del contrato es válida.")
else:
    print("La firma digital del contrato no es válida.")
