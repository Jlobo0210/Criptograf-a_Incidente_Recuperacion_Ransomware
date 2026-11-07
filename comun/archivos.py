"""
comun/archivos.py
Utilidades para escribir los archivos recuperados sin salir de la carpeta
de salida. 'nombre_original' viene del JSON cifrado y no está autenticado
por GCM, así que nunca se usa como ruta completa.
"""

from pathlib import Path


def nombre_seguro(nombre):
    """Conserva solo el nombre final del archivo (sin carpetas ni '..')."""
    base = Path(str(nombre).replace("\\", "/")).name
    if base in {"", ".", ".."}:
        raise ValueError(f"Nombre de archivo inválido en el cifrado: {nombre!r}")
    return base
