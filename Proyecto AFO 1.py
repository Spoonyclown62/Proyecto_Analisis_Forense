import Crypto.Util.number
import hashlib

bits= 1024
def dvdstring(string, longitud):
    subcadenas = []
    for i in range(0, len(string), longitud):
        subcadenas.append(string[i:i+longitud])
    return subcadenas

# Generar primos para Alice
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

na = pA * pB
phiA = (pA - 1) * (pB - 1)

# Usaremos el número primo 65537 como e para ambos
e = 65537

# Calcular la clave privada de Alice
dA = Crypto.Util.number.inverse(e, phiA)

# Generar primos para Bob
pC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pD = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

nb = pC * pD
phiB = (pC - 1) * (pD - 1)

# Calcular la clave privada de Bob
dB = Crypto.Util.number.inverse(e, phiB)

# Clave pública de Bob
public_key_bob = (nb, e)

# Clave privada de Bob
private_key_bob = dB

# Mensaje original
M = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque auctor dictum enim, vel blandit lacus pretium vitae. Integer ante massa, scelerisque et ipsum at, accumsan varius massa. Nunc tristique augue elit. Etiam cursus in nunc sed facilisis. Nunc maximus vitae diam quis dapibus. In sed mauris nisl. Vivamus imperdiet augue ultricies dolor malesuada, sit amet scelerisque urna molestie. Fusce efficitur rutrum rutrum. Pellentesque a leo at elit facilisis tristique id in risus. Maecenas euismod turpis nec est efficitur eleifend.Fusce et accumsan velit. Aliquam vitae placerat urna, at suscipit eros. Etiam auctor, arcu vitae commodo tempus, risus lacus pellentesque augue, ut tristique odio magna mollis justo. Interdum et malesuada fames ac ante ipsum primis in faucibus. Mauris erat lacus, iaculis vel fringilla sed, efficitur sit amet arcu. Maecenas ornare facilisis ante quis semper. Nam consequat nibh in quam consequat, ut iaculis ipsum consequat. Maecenas ullamcorper augue sit amet ornare maximus. Vivamus id commodo mi. Curabitur ac."
longitud_subcadena = 128

subcadenas = dvdstring(M, longitud_subcadena)

# Cifrado de mensajes por Alice
cifrado_alice = []

for subcadena in subcadenas:
    m = int.from_bytes(subcadena.encode('utf-8'), byteorder='big')
    c = pow(m, public_key_bob[1], public_key_bob[0])
    cifrado_alice.append(c)

# Descifrado por Bob
descifrado_bob = []

for c in cifrado_alice:
    m = pow(c, private_key_bob, nb)
    mensaje_descifrado = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    descifrado_bob.append(mensaje_descifrado)

# Unir los mensajes descifrados en uno solo
mensaje_descifrado_completo = "".join(descifrado_bob)

#print(M)
#print(mensaje_descifrado_completo)

# Calcular el hash del mensaje original y del mensaje descifrado
h_original = hashlib.sha256(M.encode()).hexdigest()
h_descifrado = hashlib.sha256(mensaje_descifrado_completo.encode()).hexdigest()

# Comparar los hashes
if h_original == h_descifrado:
    print("Los mensajes son iguales")
else:
    print("Los mensajes son diferentes")