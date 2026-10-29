# Actividad III: Del incidente a la recuperación

Simulación de laboratorio de un incidente de ransomware (Modelo B): la víctima genera la semilla maestra `sV` y la entrega al servidor con RSA-OAEP. Incluye recuperación por pago, recuperación por investigación, un intermediario MITM y una defensa con firmas digitales.

Este archivo explica cómo ejecutar el proyecto. El diseño, el protocolo, las mediciones y los resultados están en el informe en PDF (`informe/informe.pdf`), que se incluye en el ZIP de entrega.

## Estado del proyecto

| Componente | Estado |
|---|---|---|
| `servidor/` | Terminado: registro, entrega de `sV`, persistencia, reinicio, pago y firma de `pkS` |
| `comun/crypto_common.py`, `comun/transporte.py` | Terminado |
| `comun/firmas.py`, `pruebas/test_firmas.py` | Terminado (3 pruebas en `ok`) |
| `mitm/` | Terminado: sustitución de `pkS` por `pkM` (M2), intercepción y reenvío de la maestra (M3–M4), descifrado de copias (M6) y modo de firma propia para la prueba 4 (`--firmar-pkm`) |
| `victima/` | Terminado: registro, verificación de firma, entrega de `sV`, cifrado y recuperación por pago |
| `investigacion/` | Terminado: recuperación de `sV` por fuerza bruta (5b) con mediciones |
| `comun/generador_semillas.py` | Entregado por el profesor, sin modificar |


## Estructura

```text
comun/
  crypto_common.py        RSA-OAEP, Ki = HMAC-SHA256(sV, i), AES-256-GCM con AAD
  transporte.py           Framing TCP (longitud de 4 bytes) + mensajes JSON
  firmas.py               Firma RSA-PSS de claves públicas y verificación
  generador_semillas.py   Generador suministrado por el profesor (sin cambios)  
servidor/
  servidor.py             Servidor (puerto 5000)
  Dockerfile
  datos/                  Claves y registro del servidor (se generan solos; en Docker viven en un volumen)
victima/
  victima.py              Cliente de la víctima                                 
  datos/                  Clave de confianza clave_firma_publica.pem y datos de la víctima
mitm/
  mitm.py                 Intermediario (puerto 5001)
  Dockerfile
investigacion/
  investigar.py           Recuperación de sV sin el servidor (paso 5b)          
pruebas/
  test_firmas.py          Pruebas unitarias de firmas
scratch_cliente_prueba.py Cliente mínimo para probar el servidor sin la víctima
docker-compose.yml        Servicios servidor y mitm
.dockerignore             Evita copiar servidor/datos/ a la imagen
requirements.txt          pycryptodome==3.23.0
evidencias/               Resultados de cada prueba (se crea al preparar las pruebas)
```

`comun/generador_semillas.py` es el generador suministrado y no se modifica.

## 1. Requisitos

- Docker Desktop en ejecución, con `docker compose`.
- Python 3.12 en el equipo anfitrión (para la víctima, la investigación y las pruebas unitarias).

```powershell
docker --version
docker compose version
python --version
```

## 2. Preparar el entorno

Todos los comandos se ejecutan desde la carpeta que contiene `docker-compose.yml`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Comprobar el módulo de firmas:

```powershell
python -m unittest pruebas.test_firmas -v
```

Los tres casos (`test_firma_valida`, `test_rechaza_clave_sustituida`, `test_rechaza_identidad_distinta`) deben terminar en `ok`. Guardar la salida como evidencia:

```powershell
New-Item -ItemType Directory -Force evidencias | Out-Null
python -m unittest pruebas.test_firmas -v 2>&1 | Tee-Object evidencias\test_firmas.txt
```

## 3. Separar los datos de cada prueba

Cada prueba usa su propio proyecto de Compose (`-p`), y por tanto su propio volumen de servidor (`<proyecto>_servidor_datos`) con su propio par RSA, su propia clave de firma y su propio registro. Cada prueba tiene además su propia carpeta de evidencias. Así una prueba no reutiliza el registro ni la semilla de otra.

| Prueba | Proyecto Compose | Carpeta de evidencias | idV |
|---|---|---|---|
| 1. Cifrado y pago | `p1` | `evidencias\p1_pago` | `v-p1` |
| 2. Investigación | (sin servidor; usa copias de `p1`) | `evidencias\p2_investigacion` | `v-p1` |
| 3. MITM | `p3` | `evidencias\p3_mitm` | `v-p3` |
| 4. Firmas | `p4` | `evidencias\p4_firmas` | `v-p4-mitm`, `v-p4-firma-mitm`, `v-p4-legitima` |

> **Importante:** los proyectos publican los mismos puertos (`5000` y `5001`), así que **solo puede haber uno en marcha a la vez**. Antes de levantar `p3`, detener `p1` con `docker compose -p p1 stop`. Si `up` falla con `port is already allocated`, detener el otro proyecto y repetir el `up`; si el contenedor quedó creado sin puertos, ejecutar `docker compose -p p3 down` (sin `-v`) y volver a levantarlo.

Crear las carpetas y los archivos de trabajo (ejemplo para la prueba 1; repetir cambiando `$P` para `p3_mitm` y `p4_firmas`):

```powershell
$P = "evidencias\p1_pago"
New-Item -ItemType Directory -Force "$P\originales", "$P\trabajo", "$P\cifrados", "$P\recuperados", "$P\logs" | Out-Null

# Archivos de prueba: uno de texto y uno binario de 1 MiB
"Documento de prueba de la Actividad III" | Set-Content "$P\originales\documento.txt"
$bytes = New-Object byte[] 1048576; (New-Object Random 42).NextBytes($bytes)
[IO.File]::WriteAllBytes("$PWD\$P\originales\binario.bin", $bytes)

# La víctima trabaja sobre copias; los originales se reservan para comparar
Copy-Item "$P\originales\*" "$P\trabajo\"
```

> **Importante:** no usar `docker compose down -v` hasta terminar una prueba: `-v` borra el volumen con el registro y las claves del servidor, y la recuperación por pago deja de ser posible.

## 4. Patrón común de cada prueba

Todas las pruebas con servidor siguen los mismos pasos. Abajo solo se indica lo que cambia.

```powershell
# a) Levantar los servicios de la prueba (la primera vez construye las imágenes)
docker compose -p p1 up --build -d servidor mitm
docker compose -p p1 logs servidor
#    Debe mostrar: "Clave RSA del servidor generada y guardada.",
#    "Clave RSA de firma generada y guardada." y "Servidor escuchando en 0.0.0.0:5000"

# b) Copiar la clave pública de firma del servidor a la víctima (canal de confianza).
#    Cada proyecto genera su propia clave de firma: repetir este paso en cada prueba.
docker compose -p p1 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\

# c) Ejecutar la víctima (registro, entrega de sV y cifrado: pasos 1-3)
python victima\victima.py cifrar --id v-p1 --puerto 5000 --entrada evidencias\p1_pago\trabajo --salida evidencias\p1_pago\cifrados

# d) Cerrar y reiniciar (paso 4). El servidor recarga su par RSA y el registro desde el volumen.
docker compose -p p1 stop
docker compose -p p1 start
docker compose -p p1 logs servidor
#    Tras el reinicio debe mostrar "Clave RSA del servidor cargada." y "Clave RSA de firma cargada."

# e) Guardar las trazas
docker compose -p p1 logs servidor > evidencias\p1_pago\logs\servidor.log
```

> Los comandos de `victima.py` de arriba son los definitivos: subcomando `cifrar` (pasos 1–3) y `recuperar-pago` (5a y 6), con las opciones `--id`, `--host` (por defecto `127.0.0.1`), `--puerto`, `--entrada`, `--salida` y, para la prueba de MITM, `--sin-firmas`.

### Comprobar el servidor sin la víctima

Como comprobación rápida del servidor sin la víctima, `scratch_cliente_prueba.py` hace el recorrido completo contra el servidor: registro, verificación de la firma de `pkS`, entrega de una semilla de prueba y recuperación por pago. Requiere haber hecho el paso b).

```powershell
python scratch_cliente_prueba.py
```

Salida esperada:

```text
Registro: {'tipo': 'registro_ok', 'pks_n': '...', 'pks_e': 65537, 'pks_firma': '...'}
Firma del servidor verificada correctamente.
Entrega: {'tipo': 'entrega_ok', 'idV': 'v-prueba-003'}
Recuperación por pago OK — la semilla coincide.
```

El script usa un `idV` fijo y genera un par RSA nuevo en cada ejecución. Repetirlo contra el mismo volumen devuelve `El ID ya está registrado con otra clave pública.`, que es el comportamiento correcto del servidor. Para repetirlo, cambiar `ID_VICTIMA` o usar otro proyecto de Compose. Este script no usa `generar_semilla_maestra()` y no sustituye a la víctima en las pruebas entregadas.

## 5. Las cuatro pruebas

### Prueba 1. Cifrado y pago (pasos 1–4, 5a y 6)

Patrón común con `-p p1`, víctima en el puerto `5000`. Después del reinicio:

```powershell
python victima\victima.py recuperar-pago --id v-p1 --puerto 5000 --entrada evidencias\p1_pago\cifrados --salida evidencias\p1_pago\recuperados
docker compose -p p1 logs servidor > evidencias\p1_pago\logs\servidor.log
```

En el registro del servidor deben verse, en este orden: `Víctima registrada: v-p1`, `Semilla maestra recibida y guardada para: v-p1`, las líneas de recarga tras el reinicio y `Recuperación por pago simulado para: v-p1`. Terminar con la comparación de la sección 6.

### Prueba 2. Investigación (paso 5b)

Usa una copia de los cifrados de la prueba 1, con el servidor apagado.

```powershell
docker compose -p p1 stop
New-Item -ItemType Directory -Force evidencias\p2_investigacion\cifrados, evidencias\p2_investigacion\recuperados | Out-Null
Copy-Item evidencias\p1_pago\cifrados\* evidencias\p2_investigacion\cifrados\
Copy-Item evidencias\p1_pago\originales evidencias\p2_investigacion\ -Recurse   # solo para la comparación final

python investigacion\investigar.py --entrada evidencias\p2_investigacion\cifrados --salida evidencias\p2_investigacion\recuperados --mediciones evidencias\p2_investigacion\mediciones.csv
```

La investigación solo lee los archivos cifrados y sus metadatos. No accede a `servidor/datos`, al volumen del servidor, a claves privadas ni a los resultados de la prueba 1.

> `investigar.py` recibe `--entrada` (carpeta de cifrados), `--salida` (recuperados) y `--mediciones` (CSV); admite además `--procesos` y `--bits` (por defecto 16 procesos y 24 bits). El `mediciones.csv` registra el entorno, los procesos, el espacio de búsqueda, el archivo oráculo, la semilla encontrada, los candidatos probados y los tiempos de recuperar `sV` y de descifrar.

### Prueba 3. MITM (M1–M6)

```powershell
docker compose -p p1 stop
docker compose -p p3 up --build -d servidor mitm
docker compose -p p3 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
```

La víctima se conecta al intermediario (`--puerto 5001`) y sin comprobar firmas (`--sin-firmas`), como pide M2:

```powershell
python victima\victima.py cifrar --id v-p3 --puerto 5001 --sin-firmas --entrada evidencias\p3_mitm\trabajo --salida evidencias\p3_mitm\cifrados
```

Al terminar, con víctima y servidor cerrados (M5):

```powershell
docker compose -p p3 logs servidor > evidencias\p3_mitm\logs\servidor.log
docker compose -p p3 stop servidor
docker compose -p p3 logs mitm > evidencias\p3_mitm\logs\mitm.log
# M6: recuperación por el intermediario con la maestra interceptada.
# Tomar la semilla del log del intermediario (línea "M3: ... sV = <hex>") y descifrar las copias:
python mitm\mitm.py descifrar --id v-p3 --sv <hex-de-sV> --entrada evidencias\p3_mitm\cifrados --salida evidencias\p3_mitm\recuperados_mitm
```

> El intermediario conserva `skM`, abre la entrega de la víctima, guarda `sV` (la imprime en su traza como `sV = <hex>` y la escribe en `mitm/datos/<idV>.json`) y la re-cifra con la `pkS` real antes de reenviarla al servidor (M3–M4). El subcomando `descifrar` recupera las copias con esa maestra, con el servidor apagado (M6).

### Prueba 4. Firmas digitales

```powershell
docker compose -p p3 stop
docker compose -p p4 up --build -d servidor mitm
docker compose -p p4 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
```

Se ejecuta tres veces, cada una con un `idV` nuevo:

| Caso | idV | Puerto | Resultado esperado |
|---|---|---|---|
| Sustitución de clave | `v-p4-mitm` | `5001` | La firma `pks_firma` no verifica con la clave de confianza para `pkM`; la víctima no envía `entrega_semilla` |
| Firma propia del intermediario | `v-p4-firma-mitm` | `5001` | Rechazo: la firma es del intermediario y no verifica con la clave de confianza copiada en el paso b) |
| Intercambio legítimo | `v-p4-legitima` | `5000` | Cifrado, reinicio y recuperación por pago completos |

Comandos de la víctima para cada caso (la víctima verifica firmas; **no** se usa `--sin-firmas`):

```powershell
# Caso 1 — sustitución de clave (intermediario por defecto en 5001): debe RECHAZAR
python victima\victima.py cifrar --id v-p4-mitm --puerto 5001 --entrada evidencias\p4_firmas\trabajo --salida evidencias\p4_firmas\cifrados_caso1

# Caso 3 — intercambio legítimo (servidor directo en 5000): debe COMPLETAR
python victima\victima.py cifrar --id v-p4-legitima --puerto 5000 --entrada evidencias\p4_firmas\trabajo --salida evidencias\p4_firmas\cifrados_legitima
```

Para el **caso 2** el intermediario debe firmar `pkM` con su propia clave. Relanzarlo en ese modo (flag `--firmar-pkm`, equivalente a la variable `MITM_FIRMAR_PKM=1`) y conectar la víctima:

```powershell
docker compose -p p4 stop mitm            # liberar el puerto 5001
$env:SERVIDOR_HOST = "127.0.0.1"; $env:SERVIDOR_PORT = "5000"
python mitm\mitm.py proxy --firmar-pkm    # intermediario en modo "firma propia" (en el host)
# en otra terminal:
python victima\victima.py cifrar --id v-p4-firma-mitm --puerto 5001 --entrada evidencias\p4_firmas\trabajo --salida evidencias\p4_firmas\cifrados_caso2
```

En los dos casos de ataque la víctima rechaza antes de enviar la semilla: en el caso 1 porque el intermediario cambia `pks_n`/`pks_e` pero conserva la firma original del servidor; en el caso 2 porque la víctima verifica contra la clave de confianza del servidor real (copiada en el paso b), no contra la que entrega el intermediario. El registro del servidor debe mostrar `v-p4-mitm` y `v-p4-firma-mitm` **sin** semilla, y `v-p4-legitima` con `Semilla maestra recibida y guardada`.

> Nota: la defensa en sentido contrario (que el servidor autentique la clave de la víctima) no se implementó; no la exige ninguna de las tres pruebas de firmas.

## 6. Comparar recuperados con originales

```powershell
$P = "evidencias\p1_pago"   # cambiar por la carpeta de la prueba
Get-ChildItem "$P\originales" | ForEach-Object {
    $o = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    $r = (Get-FileHash "$P\recuperados\$($_.Name)" -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    "{0,-20} {1}" -f $_.Name, $(if ($o -eq $r) { "IDENTICO" } else { "DISTINTO o FALTA" })
} | Tee-Object "$P\comparacion.txt"
```

Para una comparación byte a byte: `fc.exe /b original recuperado`.

## 7. Limpiar

```powershell
docker compose -p p1 down      # conserva el volumen
docker compose -p p1 down -v   # borra el volumen (solo al terminar la prueba)
```

Repetir para `p3` y `p4`. `docker volume ls` muestra los volúmenes que quedan.
