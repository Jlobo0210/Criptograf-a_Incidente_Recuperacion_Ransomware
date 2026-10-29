"""
investigacion/investigar.py

Recuperación de la semilla maestra sV por investigación (paso 5b), con el
servidor apagado. Solo usa información permitida por el enunciado: el código
de la aplicación y del generador, y los archivos cifrados con sus metadatos
públicos (idV, i, nonce, etiqueta, ciphertext). No accede al registro del
servidor, a claves privadas ni a secretos guardados durante el cifrado.

Fundamento del ataque
----------------------
generar_semilla_maestra() hace:
    configuracion = secrets.randbelow(9) + 16   # entero en [16, 24]
    valor = secrets.randbelow(1 << configuracion)
    return valor.to_bytes(32, "big")
Como valor < 2**configuracion y configuracion <= 24, siempre valor < 2**24.
El parámetro 'configuracion' solo cambia la probabilidad de cada valor, no el
conjunto alcanzable: {0, ..., 2**24 - 1}. Son 2**24 = 16 777 216 semillas
posibles (24 bits de entropía real), muy por debajo de los 256 bits de una
clave AES-256. Eso hace viable la fuerza bruta.

Cómo se reconoce la semilla correcta
------------------------------------
Para un candidato se deriva Ki = HMAC-SHA256(sV, i) del archivo oráculo y se
intenta la verificación AES-GCM con su nonce, etiqueta y AAD. La propia
etiqueta GCM es el criterio: una verificación válida tiene probabilidad de
falso positivo de 2**-128, así que confirma la semilla. No hace falta otro
criterio (enunciado, paso 5b y paso 6).

Optimización
------------
El costo de verificar GCM crece con el tamaño del ciphertext, así que como
oráculo se usa el archivo cifrado más pequeño (no necesariamente i = 0):
cualquier archivo sirve, porque su Ki y su AAD se derivan de su propio i.
El rango [0, 2**24) se reparte entre varios procesos (multiprocessing).
"""

import sys
import csv
import json
import time
import base64
import argparse
import platform
import multiprocessing as mp

from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from comun.crypto_common import derivar_clave_Ki, construir_aad, descifrar_con_aad

from Crypto.Cipher import AES


BITS_MAXIMOS = 24  # Cota del generador suministrado: toda semilla es < 2**24.


# ---------------------------------------------------------------------------
# Lectura de los archivos cifrados (mismo formato que escribe la víctima)
# ---------------------------------------------------------------------------

def leer_cifrado(ruta):
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    return {
        "ruta": ruta,
        "idV": datos["idV"],
        "i": int(datos["i"]),
        "nombre_original": datos["nombre_original"],
        "nonce": base64.b64decode(datos["nonce_b64"]),
        "etiqueta": base64.b64decode(datos["etiqueta_b64"]),
        "ciphertext": base64.b64decode(datos["ciphertext_b64"]),
    }


def cargar_cifrados(carpeta):
    rutas = sorted(carpeta.glob("cifrado_*.json"))
    if not rutas:
        raise FileNotFoundError(f"No hay archivos cifrado_*.json en {carpeta}.")
    return [leer_cifrado(r) for r in rutas]


def elegir_oraculo(cifrados):
    """El archivo con el ciphertext más corto: minimiza el costo por candidato."""
    return min(cifrados, key=lambda c: len(c["ciphertext"]))


# ---------------------------------------------------------------------------
# Núcleo del ataque: prueba de un candidato
# ---------------------------------------------------------------------------

def semilla_candidata(valor):
    """Reconstruye sV de 32 bytes a partir de un entero < 2**24."""
    return valor.to_bytes(32, "big")


def candidato_valido(valor, indice, nonce, etiqueta, ciphertext, aad):
    """True si 'valor' es la semilla real (la etiqueta GCM del oráculo verifica)."""
    clave = derivar_clave_Ki(semilla_candidata(valor), indice)
    aes = AES.new(clave, AES.MODE_GCM, nonce=nonce, mac_len=16)
    aes.update(aad)
    try:
        aes.decrypt_and_verify(ciphertext, etiqueta)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Trabajadores de multiprocessing
# ---------------------------------------------------------------------------

# Parámetros estáticos del oráculo, fijados en cada proceso por el initializer.
_ORACULO = {}


def _iniciar_worker(indice, nonce, etiqueta, ciphertext, aad):
    _ORACULO.update(
        indice=indice, nonce=nonce, etiqueta=etiqueta,
        ciphertext=ciphertext, aad=aad,
    )


def _escanear_rango(rango):
    """Escanea [inicio, fin). Devuelve (semilla_o_None, candidatos_probados)."""
    inicio, fin = rango
    o = _ORACULO
    probados = 0
    for valor in range(inicio, fin):
        probados += 1
        if candidato_valido(valor, o["indice"], o["nonce"], o["etiqueta"],
                            o["ciphertext"], o["aad"]):
            return valor, probados
    return None, probados


# ---------------------------------------------------------------------------
# Búsqueda
# ---------------------------------------------------------------------------

def buscar_un_proceso(oraculo, espacio):
    """Escaneo lineal en un solo proceso (conteo exacto de candidatos)."""
    aad = construir_aad(oraculo["idV"], oraculo["i"])
    for valor in range(espacio):
        if candidato_valido(valor, oraculo["i"], oraculo["nonce"],
                            oraculo["etiqueta"], oraculo["ciphertext"], aad):
            return valor, valor + 1
    return None, espacio


def buscar_multiproceso(oraculo, espacio, procesos):
    """Reparte [0, espacio) entre procesos y se detiene al primer acierto."""
    aad = construir_aad(oraculo["idV"], oraculo["i"])

    # Muchos trozos por proceso: así la terminación temprana desperdicia poco.
    n_trozos = procesos * 64
    tam = -(-espacio // n_trozos)  # techo de la división
    rangos = [(i, min(i + tam, espacio)) for i in range(0, espacio, tam)]

    semilla = None
    probados = 0
    with mp.Pool(
        processes=procesos,
        initializer=_iniciar_worker,
        initargs=(oraculo["i"], oraculo["nonce"], oraculo["etiqueta"],
                  oraculo["ciphertext"], aad),
    ) as pool:
        for resultado, conteo in pool.imap_unordered(_escanear_rango, rangos):
            probados += conteo
            if resultado is not None:
                semilla = resultado
                pool.terminate()
                break
        else:
            pool.close()
        pool.join()

    return semilla, probados


# ---------------------------------------------------------------------------
# Descifrado de todos los archivos con la semilla recuperada (paso 6)
# ---------------------------------------------------------------------------

def descifrar_todos(cifrados, sV, carpeta_salida):
    carpeta_salida.mkdir(parents=True, exist_ok=True)
    recuperados = 0
    fallidos = []
    for c in cifrados:
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
    return recuperados, fallidos


# ---------------------------------------------------------------------------
# Mediciones
# ---------------------------------------------------------------------------

def escribir_mediciones(ruta, fila):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", newline="", encoding="utf-8") as archivo:
        escritor = csv.writer(archivo)
        escritor.writerow(fila.keys())
        escritor.writerow(fila.values())


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Recuperación de sV por investigación (fuerza bruta, 5b)."
    )
    parser.add_argument("--entrada", required=True, help="Carpeta con los cifrado_*.json.")
    parser.add_argument("--salida", required=True, help="Carpeta para los archivos recuperados.")
    parser.add_argument("--mediciones", default=None, help="Ruta del CSV de mediciones (opcional).")
    parser.add_argument("--procesos", type=int, default=mp.cpu_count(),
                        help="Procesos en paralelo (1 = escaneo lineal exacto).")
    parser.add_argument("--bits", type=int, default=BITS_MAXIMOS,
                        help=f"Bits del espacio de búsqueda (por defecto {BITS_MAXIMOS}).")
    args = parser.parse_args()

    carpeta_entrada = Path(args.entrada)
    carpeta_salida = Path(args.salida)
    espacio = 1 << args.bits

    cifrados = cargar_cifrados(carpeta_entrada)
    oraculo = elegir_oraculo(cifrados)
    procesos = max(1, args.procesos)

    print(f"Archivos cifrados: {len(cifrados)}")
    print(f"Oráculo: i={oraculo['i']} ({oraculo['nombre_original']}, "
          f"{len(oraculo['ciphertext'])} bytes de ciphertext)")
    print(f"Espacio de búsqueda: 2**{args.bits} = {espacio} candidatos")
    print(f"Procesos: {procesos}")
    print("Buscando la semilla maestra...")

    t0 = time.perf_counter()
    if procesos == 1:
        semilla, probados = buscar_un_proceso(oraculo, espacio)
    else:
        semilla, probados = buscar_multiproceso(oraculo, espacio, procesos)
    t_sv = time.perf_counter() - t0

    if semilla is None:
        print(f"No se encontró la semilla en [0, 2**{args.bits}).", file=sys.stderr)
        sys.exit(1)

    sV = semilla_candidata(semilla)
    tasa = probados / t_sv if t_sv > 0 else 0
    print(f"\nSemilla encontrada: {semilla} (0x{semilla:06x})")
    print(f"Candidatos probados: {probados}")
    print(f"Tiempo de recuperación de sV: {t_sv:.3f} s  ({tasa:,.0f} candidatos/s)")

    print("\nDescifrando archivos con la semilla recuperada...")
    t1 = time.perf_counter()
    recuperados, fallidos = descifrar_todos(cifrados, sV, carpeta_salida)
    t_descifrado = time.perf_counter() - t1

    print(f"\nRecuperados {recuperados}/{len(cifrados)} archivo(s) en {carpeta_salida}")
    print(f"Tiempo de descifrado: {t_descifrado:.3f} s")
    if fallidos:
        print(f"No recuperados: {', '.join(fallidos)}")

    if args.mediciones:
        fila = {
            "so": platform.platform(),
            "python": platform.python_version(),
            "procesos": procesos,
            "bits": args.bits,
            "espacio_busqueda": espacio,
            "oraculo_i": oraculo["i"],
            "oraculo_bytes": len(oraculo["ciphertext"]),
            "semilla_int": semilla,
            "candidatos_probados": probados,
            "tiempo_recuperar_sv_s": round(t_sv, 3),
            "candidatos_por_s": round(tasa, 1),
            "archivos": len(cifrados),
            "tiempo_descifrar_s": round(t_descifrado, 3),
            "tiempo_total_s": round(t_sv + t_descifrado, 3),
        }
        escribir_mediciones(Path(args.mediciones), fila)
        print(f"Mediciones guardadas en {args.mediciones}")


if __name__ == "__main__":
    main()
