
"""
comun/firmas.py

Funciones de firma y verificación de claves públicas RSA.
La clave pública de verificación debe obtenerse de una fuente confiable
independiente del intercambio que se está verificando.
"""

import base64
import json

from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA


def datos_clave_firmados(rol, id_victima, clave_publica):
    """
    Serialización canónica de los datos que se van a firmar.
    Incluye protocolo, rol, identidad y parámetros de la clave.
    """
    if rol not in {"servidor", "victima"}:
        raise ValueError("Rol no válido.")

    if not isinstance(id_victima, str) or not id_victima:
        raise ValueError("idV debe ser un texto no vacío.")

    datos = {
        "protocolo": "actividad-iii-v1",
        "rol": rol,
        "idV": id_victima,
        "n": str(clave_publica.n),
        "e": int(clave_publica.e),
    }

    return json.dumps(
        datos,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def firmar_clave(clave_privada_firma, rol, id_victima, clave_publica):
    """
    Firma la identidad y los parámetros de una clave pública.

    Devuelve la firma codificada en Base64 para transportarla en JSON.
    """
    if not clave_privada_firma.has_private():
        raise ValueError("Se necesita una clave privada para firmar.")

    contenido = datos_clave_firmados(
        rol,
        id_victima,
        clave_publica,
    )

    resumen = SHA256.new(contenido)
    firma = pss.new(clave_privada_firma).sign(resumen)

    return base64.b64encode(firma).decode("ascii")


def verificar_firma_clave(
    clave_publica_verificacion,
    rol,
    id_victima,
    clave_publica_cifrado,
    firma_b64,
):
    """
    Verifica la firma usando una clave de confianza obtenida por separado.

    Devuelve True si la firma es válida; False si falla la verificación
    o si la firma está mal formada.
    """
    try:
        if not isinstance(firma_b64, str):
            return False

        firma = base64.b64decode(firma_b64, validate=True)

        contenido = datos_clave_firmados(
            rol,
            id_victima,
            clave_publica_cifrado,
        )

        resumen = SHA256.new(contenido)
        pss.new(clave_publica_verificacion).verify(resumen, firma)
        return True

    except (ValueError, TypeError, KeyError):
        return False


def cargar_clave_publica_pem(ruta):
    """Carga una clave pública de confianza desde un archivo PEM."""
    clave = RSA.import_key(open(ruta, "rb").read())

    if clave.has_private():
        return clave.publickey()

    return clave
