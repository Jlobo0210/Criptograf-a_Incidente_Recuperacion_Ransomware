"""
comun/transporte.py
Framing TCP: cada paquete va precedido por su longitud en 4 bytes.
Sobre esto viaja JSON serializado a bytes.
"""

import json

MAX_PAQUETE = 8 * 1024 * 1024  # 8 MiB

def recibir_exacto(conexion, cantidad):
    datos = bytearray()
    while len(datos) < cantidad:
        parte = conexion.recv(min(65536, cantidad - len(datos)))
        if parte == b"":
            if len(datos) == 0:
                return None
            raise ConnectionError("La conexión terminó a mitad del paquete.")
        datos.extend(parte)
    return bytes(datos)

def enviar_paquete(conexion, paquete_bytes):
    if not 0 < len(paquete_bytes) <= MAX_PAQUETE:
        raise ValueError("Longitud de paquete fuera de rango.")
    prefijo = len(paquete_bytes).to_bytes(4, "big")
    conexion.sendall(prefijo + paquete_bytes)

def recibir_paquete(conexion):
    prefijo = recibir_exacto(conexion, 4)
    if prefijo is None:
        return None
    cantidad = int.from_bytes(prefijo, "big")
    if not 0 < cantidad <= MAX_PAQUETE:
        raise ValueError("Longitud anunciada fuera de rango.")
    return recibir_exacto(conexion, cantidad)

# --- Capa JSON sobre el framing -------------------------------------------

def enviar_mensaje(conexion, mensaje_dict):
    """mensaje_dict: diccionario serializable a JSON (ver formato acordado)."""
    enviar_paquete(conexion, json.dumps(mensaje_dict).encode("utf-8"))

def recibir_mensaje(conexion):
    """Devuelve el diccionario decodificado, o None si la conexión cerró."""
    paquete = recibir_paquete(conexion)
    if paquete is None:
        return None
    return json.loads(paquete.decode("utf-8"))