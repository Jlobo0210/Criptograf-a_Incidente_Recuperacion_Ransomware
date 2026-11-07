# Actividad III: Del incidente a la recuperación

Simulación de laboratorio de un incidente de ransomware (Modelo B): la víctima genera la semilla maestra `sV` y la entrega al servidor con RSA-OAEP. Incluye recuperación por pago, recuperación por investigación, un intermediario MITM y una defensa con firmas digitales en los dos sentidos (la víctima autentica `pkS` y el servidor autentica `pkV`).

Este archivo explica cómo ejecutar el proyecto. El diseño, el protocolo, las mediciones y los resultados están en `Informe.pdf`.

## Estructura

```text
comun/
  crypto_common.py        RSA-OAEP, Ki = HMAC-SHA256(sV, i), AES-256-GCM con AAD
  transporte.py           Framing TCP (longitud de 4 bytes) + mensajes JSON
  firmas.py               Firma RSA-PSS de claves públicas y verificación
  archivos.py             Nombre seguro para escribir los archivos recuperados
  generador_semillas.py   Generador suministrado por el profesor (sin cambios)
servidor/
  servidor.py             Servidor (puerto 5000)
  Dockerfile
  datos/                  Claves, registro y confianza_victimas/ (en Docker viven en un volumen)
victima/
  victima.py              Cliente de la víctima (subcomandos preparar, cifrar, recuperar-pago)
  Dockerfile
  datos/                  Clave de confianza del servidor y, por idV, los pares RSA de la víctima
mitm/
  mitm.py                 Intermediario (puerto 5001)
  Dockerfile
  datos/                  Maestras interceptadas (<idV>.json)
investigacion/
  investigar.py           Recuperación de sV sin el servidor (paso 5b)
pruebas/
  test_firmas.py                  Firma de pkS (víctima autentica al servidor)
  test_autenticacion_victima.py   Firma de pkV (servidor autentica a la víctima) y nombres seguros
scratch_cliente_prueba.py Cliente mínimo para probar el servidor sin la víctima
docker-compose.yml        Servicios servidor, mitm y victima en la red interna "laboratorio"
requirements.txt          pycryptodome==3.23.0
evidencias/               Resultados de cada prueba (se crea al preparar las pruebas)
```

## 1. Requisitos

- Docker Desktop en ejecución, con `docker compose`.
- Python 3.12 en el equipo anfitrión, solo para la investigación (paso 5b), el descifrado del MITM (M6) y las pruebas unitarias.

```powershell
docker --version
docker compose version
python --version
```

## 2. Preparar el entorno

Todos los comandos se ejecutan en PowerShell desde la carpeta que contiene `docker-compose.yml`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Pruebas unitarias (12 casos, todos deben terminar en `ok`):

```powershell
New-Item -ItemType Directory -Force evidencias | Out-Null
python -m unittest pruebas.test_firmas pruebas.test_autenticacion_victima -v 2>&1 | Tee-Object evidencias\pruebas_unitarias.txt
```

## 3. Separar los datos de cada prueba

Cada prueba usa su propio proyecto de Compose (`-p`) y por tanto su propio volumen de servidor (`<proyecto>_servidor_datos`), con su propio par RSA, su propia clave de firma y su propio registro. Cada prueba tiene además su propia carpeta de evidencias y su propio `idV`.

| Prueba | Proyecto Compose | Carpeta de evidencias | idV |
|---|---|---|---|
| 1. Cifrado y pago | `p1` | `evidencias\p1_pago` | `v-p1` |
| 2. Investigación | (sin servidor; usa copias de `p1`) | `evidencias\p2_investigacion` | `v-p1` |
| 3. MITM | `p3` | `evidencias\p3_mitm` | `v-p3` |
| 4. Firmas | `p4` | `evidencias\p4_firmas` | `v-p4-mitm`, `v-p4-firma-mitm`, `v-p4-pkv`, `v-p4-legitima` |

> **Importante:** todos los proyectos publican los puertos `5000` y `5001` en `127.0.0.1`, así que **solo puede haber uno en marcha a la vez**. Antes de levantar uno, detener el anterior con `docker compose -p <anterior> stop`.

> **Importante:** no usar `docker compose down -v` hasta terminar una prueba: `-v` borra el volumen con el registro y las claves del servidor, y la recuperación por pago deja de ser posible.

Crear las carpetas y los archivos de trabajo de las tres pruebas con servidor:

```powershell
foreach ($P in "evidencias\p1_pago", "evidencias\p3_mitm", "evidencias\p4_firmas") {
    New-Item -ItemType Directory -Force "$P\originales", "$P\trabajo", "$P\logs" | Out-Null
    # Archivos de prueba: uno de texto y uno binario de 1 MiB
    "Documento de prueba de la Actividad III" | Set-Content "$P\originales\documento.txt"
    $bytes = New-Object byte[] 1048576; (New-Object Random 42).NextBytes($bytes)
    [IO.File]::WriteAllBytes("$PWD\$P\originales\binario.bin", $bytes)
    # La víctima trabaja sobre copias; los originales se reservan para comparar
    Copy-Item "$P\originales\*" "$P\trabajo\"
}
```

## 4. Patrón común de cada prueba

Todas las pruebas con servidor siguen estos pasos. Abajo, en cada prueba, solo se indica lo que cambia. La víctima corre en su propio contenedor (`docker compose run --rm victima …`) y llega al servidor por la red interna con `--host servidor` o al intermediario con `--host mitm --puerto 5001`. Las rutas que recibe la víctima usan `/` porque se resuelven dentro del contenedor.

```powershell
# a) Construir las imágenes del proyecto (servidor, mitm y victima) y levantar servidor e intermediario
docker compose -p p1 --profile cli build
docker compose -p p1 up -d servidor mitm
docker compose -p p1 logs servidor
#    Debe mostrar "Clave RSA del servidor generada y guardada.",
#    "Clave RSA de firma generada y guardada." y "Servidor escuchando en 0.0.0.0:5000"

# b) Canal de confianza, sentido servidor -> víctima:
#    copiar la clave pública de firma del servidor a la víctima.
#    Cada proyecto genera su propia clave de firma: repetir en cada prueba.
docker compose -p p1 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\

# c) Canal de confianza, sentido víctima -> servidor:
#    generar los pares de la víctima y copiar su clave de verificación al servidor.
docker compose -p p1 run --rm victima preparar --id v-p1
docker compose -p p1 cp victima\datos\v-p1\clave_firma_publica.pem servidor:/app/servidor/datos/confianza_victimas/v-p1.pem

# d) Víctima: registro con pkV firmada, verificación de pkS, entrega de sV y cifrado (pasos 1-3)
docker compose -p p1 run --rm victima cifrar --id v-p1 --host servidor --entrada evidencias/p1_pago/trabajo --salida evidencias/p1_pago/cifrados

# e) Cerrar y reiniciar (paso 4). El servidor recarga su par RSA, su clave de firma,
#    las claves de confianza y el registro desde el volumen.
docker compose -p p1 stop
docker compose -p p1 start servidor
docker compose -p p1 logs servidor
#    Tras el reinicio debe mostrar "Clave RSA del servidor cargada." y "Clave RSA de firma cargada."
```

Subcomandos de `victima.py`: `preparar --id` (genera el par de cifrado y el de firma), `cifrar` (pasos 1–3) y `recuperar-pago` (5a y 6), con `--id`, `--host` (por defecto `127.0.0.1`), `--puerto` (por defecto `5000`), `--entrada`, `--salida` y, solo en la prueba de MITM, `--sin-firmas`.

### Comprobar el servidor sin la víctima

`scratch_cliente_prueba.py` hace el recorrido completo contra el servidor (registro firmado, verificación de `pkS`, entrega de una semilla de prueba y pago). Requiere el paso b) y, para `v-prueba-003`, el paso c) con `python victima\victima.py preparar --id v-prueba-003` y la copia de su clave al servidor. Solo funciona una vez por volumen, porque el servidor acepta una sola entrega por `idV`.

```powershell
python scratch_cliente_prueba.py
```

## 5. Las cuatro pruebas

### Prueba 1. Cifrado y pago (pasos 1–4, 5a y 6)

Patrón común completo con `-p p1` y `idV = v-p1`. Después del reinicio:

```powershell
docker compose -p p1 run --rm victima recuperar-pago --id v-p1 --host servidor --entrada evidencias/p1_pago/cifrados --salida evidencias/p1_pago/recuperados
docker compose -p p1 logs servidor > evidencias\p1_pago\logs\servidor.log
```

En la traza del servidor deben verse, en este orden: `Víctima registrada (firma de pkV verificada): v-p1`, `Semilla maestra recibida y guardada para: v-p1`, las líneas de recarga tras el reinicio y `Recuperación por pago simulado para: v-p1`. Terminar con la comparación de la sección 6.

### Prueba 2. Investigación (paso 5b)

Usa una copia de los cifrados de la prueba 1, con el servidor apagado. Se ejecuta en el anfitrión.

```powershell
docker compose -p p1 stop
New-Item -ItemType Directory -Force evidencias\p2_investigacion\cifrados | Out-Null
Copy-Item evidencias\p1_pago\cifrados\* evidencias\p2_investigacion\cifrados\
Copy-Item evidencias\p1_pago\originales evidencias\p2_investigacion\ -Recurse   # solo para la comparación final

python investigacion\investigar.py --entrada evidencias\p2_investigacion\cifrados --salida evidencias\p2_investigacion\recuperados --mediciones evidencias\p2_investigacion\mediciones.csv 2>&1 | Tee-Object evidencias\p2_investigacion\salida.txt
```

La investigación solo lee los archivos cifrados y sus metadatos. No accede a `servidor/datos`, al volumen del servidor, a claves privadas ni a los resultados de la prueba 1.

`investigar.py` recibe `--entrada`, `--salida` y `--mediciones`, y admite `--procesos` (por defecto, el número de núcleos del equipo) y `--bits` (por defecto 24). El CSV registra el entorno, los procesos, el espacio de búsqueda, el archivo oráculo, la semilla, los candidatos hasta la semilla (`semilla + 1`, porque el recorrido es creciente), su percentil, el esperado y la mediana teóricos, la tasa, el peor caso estimado y los tiempos de recuperar `sV` y de descifrar.

### Prueba 3. MITM (M1–M6)

```powershell
docker compose -p p1 stop
docker compose -p p3 --profile cli build
docker compose -p p3 up -d servidor mitm
docker compose -p p3 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
docker compose -p p3 run --rm victima preparar --id v-p3
docker compose -p p3 cp victima\datos\v-p3\clave_firma_publica.pem servidor:/app/servidor/datos/confianza_victimas/v-p3.pem
```

La víctima se conecta al intermediario y sin comprobar firmas (`--sin-firmas`), como pide M2:

```powershell
docker compose -p p3 run --rm victima cifrar --id v-p3 --host mitm --puerto 5001 --sin-firmas --entrada evidencias/p3_mitm/trabajo --salida evidencias/p3_mitm/cifrados
```

Al terminar, con víctima y servidor cerrados (M5), y el servidor apagado durante M6:

```powershell
docker compose -p p3 logs servidor > evidencias\p3_mitm\logs\servidor.log
docker compose -p p3 logs mitm > evidencias\p3_mitm\logs\mitm.log
docker compose -p p3 stop
# M6: el intermediario descifra las copias con la maestra que guardó en mitm\datos\v-p3.json
python mitm\mitm.py descifrar --id v-p3 --entrada evidencias\p3_mitm\cifrados --salida evidencias\p3_mitm\recuperados
```

En `mitm.log` se ven la sustitución (`M2: clave pública sustituida (pkS -> pkM)`), la apertura (`M3: maestra interceptada … sV = …`) y el reenvío (`M3: maestra re-cifrada con la pkS real y reenviada.`). La confirmación final es la línea `Semilla maestra recibida y guardada para: v-p3` del servidor.

En esta prueba el servidor también verifica la firma de `pkV`, y la acepta: en el Modelo B el intermediario no necesita tocar `pkV`, solo `pkS`. La defensa que detiene este ataque es la verificación de `pkS` en la víctima (prueba 4).

### Prueba 4. Firmas digitales

```powershell
docker compose -p p3 stop
docker compose -p p4 --profile cli build
docker compose -p p4 up -d servidor mitm
docker compose -p p4 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
foreach ($ID in "v-p4-mitm", "v-p4-firma-mitm", "v-p4-pkv", "v-p4-legitima") {
    docker compose -p p4 run --rm victima preparar --id $ID
    docker compose -p p4 cp "victima\datos\$ID\clave_firma_publica.pem" "servidor:/app/servidor/datos/confianza_victimas/$ID.pem"
}
```

Se ejecuta cuatro veces, cada una con un `idV` nuevo. La víctima verifica firmas en todos los casos (**no** se usa `--sin-firmas`).

| Caso | idV | Intermediario | Resultado esperado |
|---|---|---|---|
| 1. Sustitución de `pkS` | `v-p4-mitm` | Modo normal | La víctima rechaza: la firma no corresponde a `pkM`. No envía `entrega_semilla` |
| 2. Firma propia del intermediario | `v-p4-firma-mitm` | `MITM_FIRMAR_PKM=1` | La víctima rechaza: la firma no verifica con la clave de confianza. No envía `entrega_semilla` |
| 3. Sustitución de `pkV` | `v-p4-pkv` | `MITM_SUSTITUIR_PKV=1` | El servidor rechaza el registro: la firma de la víctima no cubre `pkM` |
| 4. Intercambio legítimo | `v-p4-legitima` | (sin intermediario) | Cifrado, reinicio y recuperación por pago completos |

```powershell
# Caso 1: sustitución de pkS -> debe RECHAZAR
docker compose -p p4 run --rm victima cifrar --id v-p4-mitm --host mitm --puerto 5001 --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados_caso1
docker compose -p p4 logs mitm > evidencias\p4_firmas\logs\mitm_caso1.log

# Caso 2: el intermediario firma pkM con su propia clave y adjunta su clave de verificación -> debe RECHAZAR
$env:MITM_FIRMAR_PKM = "1"; docker compose -p p4 up -d --force-recreate mitm; Remove-Item Env:MITM_FIRMAR_PKM
docker compose -p p4 run --rm victima cifrar --id v-p4-firma-mitm --host mitm --puerto 5001 --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados_caso2
docker compose -p p4 logs mitm > evidencias\p4_firmas\logs\mitm_caso2.log

# Caso 3: el intermediario sustituye pkV ante el servidor -> el SERVIDOR debe RECHAZAR
$env:MITM_SUSTITUIR_PKV = "1"; docker compose -p p4 up -d --force-recreate mitm; Remove-Item Env:MITM_SUSTITUIR_PKV
docker compose -p p4 run --rm victima cifrar --id v-p4-pkv --host mitm --puerto 5001 --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados_caso3
docker compose -p p4 logs mitm > evidencias\p4_firmas\logs\mitm_caso3.log

# Caso 4: intercambio legítimo, directo al servidor -> debe COMPLETAR cifrado, reinicio y pago
docker compose -p p4 run --rm victima cifrar --id v-p4-legitima --host servidor --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados
docker compose -p p4 stop
docker compose -p p4 start servidor
docker compose -p p4 run --rm victima recuperar-pago --id v-p4-legitima --host servidor --entrada evidencias/p4_firmas/cifrados --salida evidencias/p4_firmas/recuperados
docker compose -p p4 logs servidor > evidencias\p4_firmas\logs\servidor.log
```

En los casos 1 y 2 la víctima imprime `RECHAZO: verificar_firma_clave(...) devolvió False. No se envía 'entrega_semilla'.` En el caso 2 imprime además que ignora la clave de verificación adjunta. En el caso 3 el servidor registra `Registro rechazado: Firma de pkV ausente o inválida`. Al final, la traza del servidor muestra `v-p4-mitm` y `v-p4-firma-mitm` registradas **sin** semilla, `v-p4-pkv` rechazada y `v-p4-legitima` con `Semilla maestra recibida y guardada` y `Recuperación por pago simulado`. Para guardar la salida de la víctima de cada caso, añadir `2>&1 | Tee-Object evidencias\p4_firmas\logs\victima_casoN.txt` al comando.

## 6. Comparar recuperados con originales

```powershell
foreach ($P in "evidencias\p1_pago", "evidencias\p2_investigacion", "evidencias\p3_mitm", "evidencias\p4_firmas") {
    Get-ChildItem "$P\originales" | ForEach-Object {
        $o = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        $r = (Get-FileHash "$P\recuperados\$($_.Name)" -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        "{0,-20} {1}" -f $_.Name, $(if ($o -eq $r) { "IDENTICO" } else { "DISTINTO o FALTA" })
    } | Tee-Object "$P\comparacion.txt"
}
```

Para una comparación byte a byte: `fc.exe /b original recuperado`.

## 7. Limpiar

```powershell
docker compose -p p1 down      # conserva el volumen
docker compose -p p1 down -v   # borra el volumen (solo al terminar la prueba)
```

Repetir para `p3` y `p4`. `docker volume ls` muestra los volúmenes que quedan.

## 8. Antes de entregar el ZIP

- Incluir `evidencias\` completa.
- **No** incluir `.venv\`, `servidor\datos\*.pem`, `victima\datos\*\clave_*privada.pem` ni `mitm\datos\*.json`.
