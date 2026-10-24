"""Generación de semillas maestras para la Actividad III.

Use generar_semilla_maestra() una vez para cada víctima nueva.
La función no recibe argumentos y devuelve 32 bytes.
"""

import secrets


def generar_semilla_maestra():
    """Devuelve una nueva semilla maestra."""
    configuracion = secrets.randbelow(9) + 16
    valor = secrets.randbelow(1 << configuracion)
    return valor.to_bytes(32, byteorder="big")
