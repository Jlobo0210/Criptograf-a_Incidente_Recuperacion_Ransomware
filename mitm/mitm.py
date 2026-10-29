"""
mitm/mitm.py

Intermediario (man in the middle) del laboratorio local de la Actividad III,
Modelo B. No publicar fuera de la red aislada de Docker.

Dos modos:
  proxy      (por defecto) Proxy TCP víctima <-> intermediario <-> servidor.
             Implementa M2-M4: sustituye pkS por pkM ante la víctima, abre la
             entrega de la maestra con skM, conserva sV y la reenvía al
             servidor re-cifrada con la pkS real.
  descifrar  (M6) Con la maestra interceptada, descifra copias de los archivos
             cifrados sin pagar y con el servidor apagado.

Resumen del ataque (Modelo B)
-----------------------------
M2  La víctima pide registrarse; el servidor responde con pkS. El
    intermediario entrega pkM a la víctima en lugar de pkS, pero reenvía pkV
    al servidor sin cambios y conserva la pkS real.
M3  La víctima cifra sV con pkM creyéndola del servidor. El intermediario la
    abre con skM, guarda sV y re-cifra la MISMA sV con la pkS real.
M4  El servidor recibe la entrega como si viniera de la víctima, la abre con
    skS y confirma. La confirmación se reenvía a la víctima.
M5  La víctima deriva las Ki de sV y guarda los archivos cifrados. El
    intermediario ya tiene sV.
M6  Con sV, el intermediario regenera las Ki y descifra las copias.

RSA-OAEP no impide esto: solo garantiza confidencialidad frente a quien no
tiene la clave privada usada para cifrar. Como la víctima cifró con pkM (sin
autenticar a quién pertenece), el intermediario -dueño de skM- puede abrir la
entrega. La defensa es autenticar la clave con firmas (prueba 4).
"""

import sys
import json
import socket
import base64
import argparse

from pathlib import Path
from threading import Thread

sys.path.append(str(Path(__file__).resolve().parent.parent))

from comun.transporte import enviar_mensaje, recibir_mensaje
from comun.crypto_common import (
    generar_par_rsa,
    exportar_publica,
    reconstruir_publica,
    desencapsular_oaep,
    encapsular_oaep,
    derivar_clave_Ki,
    construir_aad,
    descifrar_con_aad,
)
from comun.firmas import firmar_clave

import os


HOST = "0.0.0.0"
PUERTO = int(os.environ.get("MITM_PORT", "5001"))

SERVIDOR_HOST = os.environ.get("SERVIDOR_HOST", "servidor")
SERVIDOR_PUERTO = int(os.environ.get("SERVIDOR_PORT", "5000"))

CARPETA_DATOS = Path(__file__).resolve().parent / "datos"


# ---------------------------------------------------------------------------
# Persistencia de la maestra interceptada
# ---------------------------------------------------------------------------

def ruta_maestra(id_victima):
    return CARPETA_DATOS / f"{id_victima}.json"


def guardar_maestra(id_victima, sV):
    """Conserva sV interceptada para poder usarla en M6 tras cerrar procesos."""
    CARPETA_DATOS.mkdir(parents=True, exist_ok=True)
    ruta_maestra(id_victima).write_text(
        json.dumps({"idV": id_victima, "sV_hex": sV.hex()}, indent=2),
        encoding="utf-8",
    )


def cargar_maestra(id_victima):
    ruta = ruta_maestra(id_victima)
    if not ruta.exists():
        raise FileNotFoundError(
            f"No hay maestra interceptada para '{id_victima}' en {ruta}. "
            "Ejecute primero el proxy, o pase la semilla con --sv."
        )
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    return bytes.fromhex(datos["sV_hex"])


# ---------------------------------------------------------------------------
# Modo proxy (M2 - M4)
# ---------------------------------------------------------------------------

def procesar_conexion(conexion_victima, direccion, clave_privada_mitm,
                      clave_firma_mitm=None):
    """Reenvía el protocolo entre víctima y servidor, sustituyendo pkS por pkM
    e interceptando la entrega de la maestra.

    Si clave_firma_mitm no es None (prueba 4, caso 2), el intermediario firma
    pkM con su propia clave de firma y adjunta su clave de verificación. La
    víctima debe rechazarlo igualmente, porque verifica contra la clave de
    confianza pre-compartida, no contra la que le entrega el atacante.
    """
    print(f"Conexión de laboratorio desde {direccion}")
    clave_publica_mitm = clave_privada_mitm.publickey()

    try:
        with conexion_victima:
            with socket.create_connection(
                (SERVIDOR_HOST, SERVIDOR_PUERTO), timeout=10,
            ) as conexion_servidor:

                # --- M2: registro ------------------------------------------
                solicitud = recibir_mensaje(conexion_victima)
                if not isinstance(solicitud, dict):
                    return
                if solicitud.get("tipo") != "registro":
                    enviar_mensaje(conexion_victima, {
                        "tipo": "error",
                        "detalle": "Se esperaba un mensaje de registro.",
                    })
                    return

                id_victima = solicitud.get("idV")

                # Reenvía el registro (idV y pkV) al servidor sin cambios.
                enviar_mensaje(conexion_servidor, solicitud)
                respuesta = recibir_mensaje(conexion_servidor)
                if not isinstance(respuesta, dict):
                    return
                if respuesta.get("tipo") != "registro_ok":
                    enviar_mensaje(conexion_victima, respuesta)
                    return

                # Conserva la pkS real para re-cifrar la maestra en M3.
                pk_servidor_real = reconstruir_publica({
                    "n": respuesta["pks_n"],
                    "e": respuesta["pks_e"],
                })

                # Sustituye pkS por pkM ante la víctima. La firma original
                # (si viene) se conserva sin modificar: en la prueba 4 la
                # víctima la rechazará porque no corresponde a pkM.
                clave_mitm = exportar_publica(clave_publica_mitm)
                respuesta_modificada = dict(respuesta)
                respuesta_modificada["pks_n"] = clave_mitm["n"]
                respuesta_modificada["pks_e"] = clave_mitm["e"]

                if clave_firma_mitm is not None:
                    # Caso 2: el intermediario firma pkM con SU propia clave de
                    # firma y adjunta su clave de verificación.
                    respuesta_modificada["pks_firma"] = firmar_clave(
                        clave_firma_mitm, "servidor", id_victima, clave_publica_mitm
                    )
                    pub_firma = exportar_publica(clave_firma_mitm.publickey())
                    respuesta_modificada["pks_firma_pub_n"] = pub_firma["n"]
                    respuesta_modificada["pks_firma_pub_e"] = pub_firma["e"]
                    print(f"M2: pkM firmada con la clave de firma del intermediario "
                          f"para {id_victima}")
                else:
                    print(f"M2: clave pública sustituida (pkS -> pkM) para {id_victima}")

                enviar_mensaje(conexion_victima, respuesta_modificada)

                # --- M3-M4 y reenvío del resto del protocolo ---------------
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

                    if mensaje.get("tipo") == "entrega_semilla":
                        # M3: abrir con skM, conservar sV y re-cifrar con pkS real.
                        try:
                            encapsulacion = base64.b64decode(
                                mensaje["encapsulacion_b64"], validate=True
                            )
                            sV = desencapsular_oaep(clave_privada_mitm, encapsulacion)
                        except (ValueError, TypeError, KeyError) as error:
                            enviar_mensaje(conexion_victima, {
                                "tipo": "error",
                                "detalle": f"El intermediario no pudo abrir la maestra: {error}",
                            })
                            return

                        guardar_maestra(id_victima, sV)
                        print(f"M3: maestra interceptada de {id_victima}")
                        print(f"    sV = {sV.hex()}")
                        print(f"    guardada en {ruta_maestra(id_victima)}")

                        nueva = encapsular_oaep(pk_servidor_real, sV)
                        mensaje = dict(mensaje)
                        mensaje["encapsulacion_b64"] = base64.b64encode(
                            nueva
                        ).decode("ascii")
                        print("M3: maestra re-cifrada con la pkS real y reenviada.")

                    # Reenvía la (posiblemente reescrita) solicitud al servidor
                    # y la respuesta de vuelta a la víctima (M4 para la entrega).
                    enviar_mensaje(conexion_servidor, mensaje)
                    respuesta = recibir_mensaje(conexion_servidor)
                    if respuesta is None:
                        return
                    enviar_mensaje(conexion_victima, respuesta)

    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Conexión de laboratorio finalizada: {error}")


def ejecutar_proxy(args):
    # El par de cifrado del intermediario vive solo en memoria.
    clave_privada_mitm, _ = generar_par_rsa(2048)

    # Caso 2 de la prueba de firmas: por flag --firmar-pkm o variable de
    # entorno MITM_FIRMAR_PKM=1 (útil en Docker).
    firmar = getattr(args, "firmar_pkm", False) or os.environ.get("MITM_FIRMAR_PKM") == "1"
    clave_firma_mitm = None
    if firmar:
        clave_firma_mitm, _ = generar_par_rsa(2048)
        print("Modo caso 2: el intermediario firmará pkM con su propia clave de firma.")

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
                args=(conexion, direccion, clave_privada_mitm, clave_firma_mitm),
                daemon=True,
            )
            hilo.start()
    except KeyboardInterrupt:
        print("\nProxy detenido.")
    finally:
        escucha.close()


# ---------------------------------------------------------------------------
# Modo descifrar (M6): recuperar los archivos con la maestra interceptada
# ---------------------------------------------------------------------------

def leer_cifrado(ruta):
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    return {
        "idV": datos["idV"],
        "i": int(datos["i"]),
        "nombre_original": datos["nombre_original"],
        "nonce": base64.b64decode(datos["nonce_b64"]),
        "etiqueta": base64.b64decode(datos["etiqueta_b64"]),
        "ciphertext": base64.b64decode(datos["ciphertext_b64"]),
    }


def ejecutar_descifrar(args):
    carpeta_entrada = Path(args.entrada)
    carpeta_salida = Path(args.salida)

    cifrados = sorted(carpeta_entrada.glob("cifrado_*.json"))
    if not cifrados:
        raise FileNotFoundError(f"No hay archivos cifrado_*.json en {carpeta_entrada}.")

    if args.sv:
        sV = bytes.fromhex(args.sv)
        if len(sV) != 32:
            raise ValueError("La semilla --sv debe tener 32 bytes (64 hex).")
    else:
        sV = cargar_maestra(args.id)

    print(f"M6: descifrando {len(cifrados)} archivo(s) con la maestra interceptada.")
    carpeta_salida.mkdir(parents=True, exist_ok=True)
    recuperados = 0
    fallidos = []
    for ruta in cifrados:
        c = leer_cifrado(ruta)
        clave = derivar_clave_Ki(sV, c["i"])
        aad = construir_aad(c["idV"], c["i"])
        try:
            claro = descifrar_con_aad(
                clave, c["nonce"], c["etiqueta"], c["ciphertext"], aad
            )
        except ValueError:
            fallidos.append(c["nombre_original"])
            print(f"  [i={c['i']}] {c['nombre_original']}: ETIQUETA INVÁLIDA")
            continue
        (carpeta_salida / c["nombre_original"]).write_bytes(claro)
        recuperados += 1
        print(f"  [i={c['i']}] {c['nombre_original']}: OK")

    print(f"M6: recuperados {recuperados}/{len(cifrados)} archivo(s) en {carpeta_salida}")
    if fallidos:
        print(f"No recuperados: {', '.join(fallidos)}")


# ---------------------------------------------------------------------------
# Línea de comandos
# ---------------------------------------------------------------------------

def construir_parser():
    parser = argparse.ArgumentParser(
        description="Intermediario MITM del laboratorio (Modelo B)."
    )
    sub = parser.add_subparsers(dest="comando")

    p_proxy = sub.add_parser("proxy", help="Proxy MITM (M2-M4). Modo por defecto.")
    p_proxy.add_argument(
        "--firmar-pkm", action="store_true",
        help="Prueba 4, caso 2: firmar pkM con la clave de firma propia del "
             "intermediario (equivale a MITM_FIRMAR_PKM=1).",
    )
    p_proxy.set_defaults(func=ejecutar_proxy)

    p_desc = sub.add_parser(
        "descifrar", help="Descifra copias con la maestra interceptada (M6)."
    )
    p_desc.add_argument("--id", required=True, help="idV de la víctima interceptada.")
    p_desc.add_argument("--entrada", required=True, help="Carpeta con copias de cifrado_*.json.")
    p_desc.add_argument("--salida", required=True, help="Carpeta para los archivos recuperados.")
    p_desc.add_argument(
        "--sv", default=None,
        help="Maestra interceptada en hex (64 caracteres). Si se omite, se lee "
             "de mitm/datos/<idV>.json.",
    )
    p_desc.set_defaults(func=ejecutar_descifrar)

    return parser


def main():
    parser = construir_parser()
    args = parser.parse_args()
    # Sin subcomando (como en el Dockerfile): se ejecuta el proxy.
    if getattr(args, "func", None) is None:
        ejecutar_proxy(args)
        return
    try:
        args.func(args)
    except (OSError, ValueError, RuntimeError, FileNotFoundError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
