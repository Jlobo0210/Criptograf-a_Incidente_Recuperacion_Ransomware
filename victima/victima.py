"""
victima/victima.py

Rol: víctima del Modelo B.

Dos subcomandos:
  cifrar          Registro, entrega de la semilla maestra sV al servidor
                  (OAEP) y cifrado de los archivos de trabajo (pasos 1-3).
  recuperar-pago  Recuperación de sV por pago (5a) y descifrado de los
                  archivos (paso 6).

La víctima persiste únicamente su idV y su par RSA. Nunca guarda sV, las
claves Ki ni la entrega OAEP inicial: tras un reinicio solo quedan en disco
el par RSA, el idV y los archivos cifrados (enunciado, paso 4).
"""

import sys
import re
import json
import base64
import socket
import argparse

from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from comun.transporte import enviar_mensaje, recibir_mensaje
from comun.crypto_common import (
    generar_par_rsa,
    exportar_publica,
    reconstruir_publica,
    encapsular_oaep,
    desencapsular_oaep,
    derivar_clave_Ki,
    construir_aad,
    cifrar_con_aad,
    descifrar_con_aad,
)
from comun.firmas import cargar_clave_publica_pem, verificar_firma_clave
from comun.generador_semillas import generar_semilla_maestra

from Crypto.PublicKey import RSA


CARPETA_DATOS = Path(__file__).resolve().parent / "datos"
RUTA_CLAVE_CONFIANZA = CARPETA_DATOS / "clave_firma_publica.pem"

# Un idV válido se usa como nombre de carpeta: se restringe a caracteres
# seguros para evitar recorridos de ruta.
PATRON_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# ---------------------------------------------------------------------------
# Identidad de la víctima: idV + par RSA persistente
# ---------------------------------------------------------------------------

def validar_id(id_victima):
    if not PATRON_ID.match(id_victima):
        raise ValueError(
            "idV inválido: use solo letras, dígitos, '.', '_' o '-' "
            "(1 a 64 caracteres)."
        )
    return id_victima


def ruta_clave_victima(id_victima):
    return CARPETA_DATOS / id_victima / "clave_privada.pem"


def cargar_o_generar_clave_victima(id_victima):
    """Carga el par RSA de esta víctima o lo genera la primera vez.

    La clave debe persistir: el servidor cifra sV con la pkV registrada
    durante el cifrado, así que la recuperación por pago solo abre si skV
    es la misma.
    """
    ruta = ruta_clave_victima(id_victima)

    if ruta.exists():
        clave_privada = RSA.import_key(ruta.read_bytes())
        if not clave_privada.has_private():
            raise ValueError("El archivo de clave de la víctima no es privada.")
        if clave_privada.size_in_bits() < 2048:
            raise ValueError("La clave RSA de la víctima debe tener >= 2048 bits.")
        return clave_privada, clave_privada.publickey()

    ruta.parent.mkdir(parents=True, exist_ok=True)
    clave_privada, clave_publica = generar_par_rsa(2048)
    with open(ruta, "xb") as archivo:
        archivo.write(clave_privada.export_key())
    print(f"Par RSA de la víctima generado y guardado para: {id_victima}")
    return clave_privada, clave_publica


def cargar_clave_victima(id_victima):
    """Carga el par RSA existente (recuperación). Falla si no existe."""
    ruta = ruta_clave_victima(id_victima)
    if not ruta.exists():
        raise FileNotFoundError(
            f"No hay par RSA guardado para '{id_victima}'. "
            "Ejecute primero el subcomando 'cifrar'."
        )
    clave_privada = RSA.import_key(ruta.read_bytes())
    if not clave_privada.has_private():
        raise ValueError("El archivo de clave de la víctima no es privada.")
    return clave_privada, clave_privada.publickey()


# ---------------------------------------------------------------------------
# Comunicación con el servidor
# ---------------------------------------------------------------------------

def conectar(host, puerto):
    conexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conexion.connect((host, puerto))
    return conexion


def esperar_respuesta(conexion, tipo_esperado):
    """Recibe un mensaje y comprueba su tipo; convierte 'error' en excepción."""
    respuesta = recibir_mensaje(conexion)
    if respuesta is None:
        raise ConnectionError("El servidor cerró la conexión sin responder.")
    if not isinstance(respuesta, dict):
        raise ValueError("Respuesta del servidor con formato inesperado.")
    tipo = respuesta.get("tipo")
    if tipo == "error":
        raise RuntimeError(f"El servidor respondió un error: {respuesta.get('detalle')}")
    if tipo != tipo_esperado:
        raise RuntimeError(
            f"Se esperaba '{tipo_esperado}' y llegó '{tipo}': {respuesta}"
        )
    return respuesta


def registrar(conexion, id_victima, clave_publica_victima):
    """Paso 1: envía el registro y devuelve la respuesta registro_ok."""
    pkv = exportar_publica(clave_publica_victima)
    enviar_mensaje(conexion, {
        "tipo": "registro",
        "idV": id_victima,
        "pkv_n": pkv["n"],
        "pkv_e": pkv["e"],
    })
    return esperar_respuesta(conexion, "registro_ok")


def obtener_clave_servidor(respuesta_registro, id_victima, verificar_firmas):
    """Reconstruye pkS y, salvo que se desactiven las firmas, la autentica
    con la clave de confianza obtenida por un canal independiente.

    Devuelve la clave pública del servidor, o None si la firma no verifica
    (en cuyo caso NO debe enviarse la semilla).
    """
    pk_servidor = reconstruir_publica({
        "n": respuesta_registro["pks_n"],
        "e": respuesta_registro["pks_e"],
    })

    if not verificar_firmas:
        print("AVISO: verificación de firmas desactivada (--sin-firmas).")
        return pk_servidor

    if not RUTA_CLAVE_CONFIANZA.exists():
        raise FileNotFoundError(
            f"No se encontró la clave de confianza en {RUTA_CLAVE_CONFIANZA}. "
            "Cópiela del servidor antes de ejecutar la víctima, o use "
            "--sin-firmas para la prueba de MITM."
        )

    clave_confianza = cargar_clave_publica_pem(RUTA_CLAVE_CONFIANZA)
    firma_valida = verificar_firma_clave(
        clave_confianza,
        "servidor",
        id_victima,
        pk_servidor,
        respuesta_registro.get("pks_firma"),
    )
    if not firma_valida:
        return None

    print("Firma de la clave del servidor verificada correctamente.")
    return pk_servidor


# ---------------------------------------------------------------------------
# Formato en disco de los archivos cifrados
# ---------------------------------------------------------------------------

def nombre_cifrado(indice):
    """Nombre del JSON de cada archivo; el relleno a 6 dígitos mantiene el
    orden al listar la carpeta."""
    return f"cifrado_{indice:06d}.json"


def escribir_cifrado(carpeta_salida, id_victima, indice, nombre_original,
                     nonce, etiqueta, ciphertext):
    """Guarda un archivo cifrado autocontenido: con idV e i basta para
    reconstruir el AAD y, con la semilla, descifrarlo."""
    registro = {
        "idV": id_victima,
        "i": indice,
        "nombre_original": nombre_original,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "etiqueta_b64": base64.b64encode(etiqueta).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    ruta = carpeta_salida / nombre_cifrado(indice)
    ruta.write_text(json.dumps(registro, indent=2), encoding="utf-8")
    return ruta


def leer_cifrado(ruta):
    """Lee un JSON de archivo cifrado y devuelve sus campos ya decodificados."""
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    return {
        "idV": datos["idV"],
        "i": int(datos["i"]),
        "nombre_original": datos["nombre_original"],
        "nonce": base64.b64decode(datos["nonce_b64"]),
        "etiqueta": base64.b64decode(datos["etiqueta_b64"]),
        "ciphertext": base64.b64decode(datos["ciphertext_b64"]),
    }


# ---------------------------------------------------------------------------
# Subcomando: cifrar (pasos 1-3)
# ---------------------------------------------------------------------------

def comando_cifrar(args):
    id_victima = validar_id(args.id)
    carpeta_entrada = Path(args.entrada)
    carpeta_salida = Path(args.salida)

    if not carpeta_entrada.is_dir():
        raise NotADirectoryError(f"La carpeta de entrada no existe: {carpeta_entrada}")

    archivos = sorted(p for p in carpeta_entrada.iterdir() if p.is_file())
    if not archivos:
        raise FileNotFoundError(f"No hay archivos en {carpeta_entrada}.")

    # Paso 1 (local): par RSA de la víctima.
    clave_privada_victima, clave_publica_victima = (
        cargar_o_generar_clave_victima(id_victima)
    )

    conexion = conectar(args.host, args.puerto)
    try:
        # Paso 1: registro y obtención de pkS.
        respuesta_registro = registrar(conexion, id_victima, clave_publica_victima)

        pk_servidor = obtener_clave_servidor(
            respuesta_registro, id_victima, verificar_firmas=not args.sin_firmas
        )
        if pk_servidor is None:
            # Defensa activa: la firma no verifica -> no se expone la maestra.
            raise RuntimeError(
                "Firma del servidor inválida: se cancela el intercambio y NO "
                "se envía la semilla maestra."
            )

        # Paso 2: generar sV, conservarla solo en memoria y entregarla.
        sV = generar_semilla_maestra()
        encapsulacion = encapsular_oaep(pk_servidor, sV)
        enviar_mensaje(conexion, {
            "tipo": "entrega_semilla",
            "idV": id_victima,
            "encapsulacion_b64": base64.b64encode(encapsulacion).decode("ascii"),
        })
        esperar_respuesta(conexion, "entrega_ok")
        print("Semilla maestra entregada y confirmada por el servidor.")
    finally:
        conexion.close()

    # Paso 3: cifrar cada archivo con Ki = HMAC(sV, i) y AES-GCM (AAD = idV||i).
    carpeta_salida.mkdir(parents=True, exist_ok=True)
    for indice, ruta_archivo in enumerate(archivos):
        contenido = ruta_archivo.read_bytes()
        clave_Ki = derivar_clave_Ki(sV, indice)
        aad = construir_aad(id_victima, indice)
        nonce, etiqueta, ciphertext = cifrar_con_aad(clave_Ki, contenido, aad)
        destino = escribir_cifrado(
            carpeta_salida, id_victima, indice, ruta_archivo.name,
            nonce, etiqueta, ciphertext,
        )
        print(f"  [i={indice}] {ruta_archivo.name} -> {destino.name}")

    # La semilla y las claves derivadas se descartan al terminar el proceso:
    # no se escriben en disco.
    print(f"Cifrado completo: {len(archivos)} archivo(s) en {carpeta_salida}")


# ---------------------------------------------------------------------------
# Subcomando: recuperar-pago (5a + paso 6)
# ---------------------------------------------------------------------------

def comando_recuperar_pago(args):
    id_victima = validar_id(args.id)
    carpeta_entrada = Path(args.entrada)
    carpeta_salida = Path(args.salida)

    if not carpeta_entrada.is_dir():
        raise NotADirectoryError(f"La carpeta de cifrados no existe: {carpeta_entrada}")

    cifrados = sorted(carpeta_entrada.glob("cifrado_*.json"))
    if not cifrados:
        raise FileNotFoundError(
            f"No hay archivos cifrado_*.json en {carpeta_entrada}."
        )

    clave_privada_victima, _ = cargar_clave_victima(id_victima)

    # Paso 5a: solicitar la recuperación por pago y abrir sV con skV.
    conexion = conectar(args.host, args.puerto)
    try:
        enviar_mensaje(conexion, {"tipo": "recuperar_pago", "idV": id_victima})
        respuesta = esperar_respuesta(conexion, "recuperacion")
        encapsulacion = base64.b64decode(respuesta["encapsulacion_b64"])
    finally:
        conexion.close()

    sV = desencapsular_oaep(clave_privada_victima, encapsulacion)
    print("Semilla maestra recuperada por pago.")

    # Paso 6: regenerar cada Ki, descifrar y verificar GCM.
    carpeta_salida.mkdir(parents=True, exist_ok=True)
    recuperados = 0
    fallidos = []
    for ruta in cifrados:
        datos = leer_cifrado(ruta)
        if datos["idV"] != id_victima:
            print(f"  AVISO: {ruta.name} tiene idV '{datos['idV']}', se omite.")
            continue
        clave_Ki = derivar_clave_Ki(sV, datos["i"])
        aad = construir_aad(datos["idV"], datos["i"])
        try:
            claro = descifrar_con_aad(
                clave_Ki, datos["nonce"], datos["etiqueta"],
                datos["ciphertext"], aad,
            )
        except ValueError:
            # Etiqueta GCM inválida: el resultado se rechaza (enunciado, paso 6).
            fallidos.append(datos["nombre_original"])
            print(f"  [i={datos['i']}] {datos['nombre_original']}: ETIQUETA INVÁLIDA, rechazado")
            continue
        (carpeta_salida / datos["nombre_original"]).write_bytes(claro)
        recuperados += 1
        print(f"  [i={datos['i']}] {datos['nombre_original']}: OK")

    print(f"Recuperados {recuperados} archivo(s) en {carpeta_salida}")
    if fallidos:
        print(f"No se pudieron recuperar: {', '.join(fallidos)}")


# ---------------------------------------------------------------------------
# Línea de comandos
# ---------------------------------------------------------------------------

def construir_parser():
    parser = argparse.ArgumentParser(
        description="Cliente de la víctima (Modelo B, Actividad III)."
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    comun = argparse.ArgumentParser(add_help=False)
    comun.add_argument("--id", required=True, help="Identificador de la víctima (idV).")
    comun.add_argument("--host", default="127.0.0.1", help="Host del servidor (por defecto 127.0.0.1).")
    comun.add_argument("--puerto", type=int, default=5000, help="Puerto del servidor o del MITM.")
    comun.add_argument("--entrada", required=True, help="Carpeta de entrada.")
    comun.add_argument("--salida", required=True, help="Carpeta de salida.")

    p_cifrar = sub.add_parser(
        "cifrar", parents=[comun],
        help="Registro, entrega de sV y cifrado de los archivos (pasos 1-3).",
    )
    p_cifrar.add_argument(
        "--sin-firmas", action="store_true",
        help="No verificar la firma de pkS (prueba de MITM, M2).",
    )
    p_cifrar.set_defaults(func=comando_cifrar)

    p_pago = sub.add_parser(
        "recuperar-pago", parents=[comun],
        help="Recuperación de sV por pago y descifrado (5a y paso 6).",
    )
    p_pago.set_defaults(func=comando_recuperar_pago)

    return parser


def main():
    parser = construir_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ValueError, RuntimeError, ConnectionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
