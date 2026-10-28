
"""
mitm/mitm.py

Proxy TCP para el laboratorio local de la Actividad III.
Permite probar la detección de sustitución de clave pública en el
intercambio inicial del Modelo B.

No publicar este servicio fuera de la red aislada de Docker.
"""

import sys
import json
import socket
import os

from pathlib import Path
from threading import Thread

sys.path.append(str(Path(__file__).resolve().parent.parent))

from comun.transporte import enviar_mensaje, recibir_mensaje
from comun.crypto_common import generar_par_rsa, exportar_publica


HOST = "0.0.0.0"
PUERTO = int(os.environ.get("MITM_PORT", "5001"))

SERVIDOR_HOST = os.environ.get("SERVIDOR_HOST", "servidor")
SERVIDOR_PUERTO = int(os.environ.get("SERVIDOR_PORT", "5000"))


def procesar_conexion(conexion_victima, direccion, clave_publica_mitm):
    """
    Reenvía los mensajes del cliente al servidor y las respuestas
    del servidor al cliente. En el registro, modifica la clave pública
    anunciada para que el cliente de prueba pueda detectar el cambio.
    """
    print(f"Conexión de laboratorio desde {direccion}")

    try:
        with conexion_victima:
            with socket.create_connection(
                (SERVIDOR_HOST, SERVIDOR_PUERTO),
                timeout=10,
            ) as conexion_servidor:

                # El primer mensaje esperado es el registro.
                solicitud = recibir_mensaje(conexion_victima)

                if not isinstance(solicitud, dict):
                    return

                if solicitud.get("tipo") != "registro":
                    enviar_mensaje(conexion_victima, {
                        "tipo": "error",
                        "detalle": "Se esperaba un mensaje de registro.",
                    })
                    return

                # Reenvía el registro sin alterar la identidad ni la clave
                # pública de cifrado que el servidor recibe.
                enviar_mensaje(conexion_servidor, solicitud)
                respuesta = recibir_mensaje(conexion_servidor)

                if not isinstance(respuesta, dict):
                    return

                if respuesta.get("tipo") != "registro_ok":
                    enviar_mensaje(conexion_victima, respuesta)
                    return

                # En la prueba sin firmas, la clave se sustituye.
                # Si la respuesta lleva una firma de la clave original,
                # se conserva sin modificar: la víctima debe rechazarla.
                clave_mitm = exportar_publica(clave_publica_mitm)

                respuesta_modificada = dict(respuesta)
                respuesta_modificada["pks_n"] = clave_mitm["n"]
                respuesta_modificada["pks_e"] = clave_mitm["e"]

                print(
                    "Prueba de sustitución: se modificó la clave pública "
                    "presentada a la víctima."
                )

                enviar_mensaje(
                    conexion_victima,
                    respuesta_modificada,
                )

                # Desde este punto se reenvían las solicitudes y respuestas
                # del protocolo sin modificar sus campos.
                while True:
                    mensaje = recibir_mensaje(conexion_victima)

                    if mensaje is None:
                        return

                    if not isinstance(mensaje, dict):
                        enviar_mensaje(conexion_victima, {
                            "tipo": "error",
                            "detalle": "Mensaje inválido en el proxy.",
                        })
                        return

                    enviar_mensaje(conexion_servidor, mensaje)
                    respuesta = recibir_mensaje(conexion_servidor)

                    if respuesta is None:
                        return

                    enviar_mensaje(conexion_victima, respuesta)

    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Conexión de laboratorio finalizada: {error}")


def main():
    # La clave se crea solo en memoria para esta ejecución de prueba.
    _, clave_publica_mitm = generar_par_rsa(2048)

    escucha = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escucha.bind((HOST, PUERTO))
    escucha.listen()

    print(f"Proxy de laboratorio escuchando en {HOST}:{PUERTO}")
    print(f"Servidor de destino: {SERVIDOR_HOST}:{SERVIDOR_PUERTO}")

    try:
        while True:
            conexion, direccion = escucha.accept()

            hilo = Thread(
                target=procesar_conexion,
                args=(conexion, direccion, clave_publica_mitm),
                daemon=True,
            )
            hilo.start()

    except KeyboardInterrupt:
        print("\nProxy detenido.")

    finally:
        escucha.close()


if __name__ == "__main__":
    main()
