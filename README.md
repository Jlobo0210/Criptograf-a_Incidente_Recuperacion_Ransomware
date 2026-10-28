# Actividad III: Del incidente a la recuperación

Simulación de laboratorio de un incidente de ransomware (Modelo B): la víctima genera la semilla maestra y la entrega al servidor con RSA-OAEP. Incluye recuperación por pago, recuperación por investigación, un intermediario MITM y una defensa con firmas digitales.

Este archivo solo explica cómo ejecutar el proyecto. El diseño, las mediciones y los resultados están en el informe PDF.

## Estructura

```text
comun/          Funciones compartidas (RSA-OAEP, HMAC, AES-GCM, firmas, transporte TCP)
servidor/       Servidor (puerto 5000). Datos persistentes en servidor/datos/
victima/        Cliente de la víctima. Clave de confianza en victima/datos/
mitm/           Intermediario (puerto 5001)
pruebas/        Pruebas unitarias de firmas
evidencias/     Resultados de cada prueba (se crea al preparar el entorno)
```

`comun/generador_semillas.py` es el generador suministrado y no se ha modificado.

## 1. Requisitos

- Docker Desktop en ejecución, con `docker compose`.
- Python 3.12 (para la víctima, la investigación y las pruebas unitarias).

```powershell
docker --version
docker compose version
python --version
```

## 2. Preparar el entorno

Desde la carpeta que contiene `docker-compose.yml`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Comprobar el módulo de firmas:

```powershell
python -m unittest pruebas.test_firmas -v
```

Los tres casos deben terminar en `ok`.

## 3. Separar los datos de cada prueba

Cada prueba usa su propio proyecto de Compose (`-p`), y por tanto su propio volumen de servidor, y su propia carpeta de evidencias. Así una prueba no reutiliza el registro ni la semilla de otra.

| Prueba | Proyecto Compose | Carpeta de evidencias | idV |
|---|---|---|---|
| 1. Cifrado y pago | `p1` | `evidencias\p1_pago` | `v-p1` |
| 2. Investigación | (reutiliza `p1`) | `evidencias\p2_investigacion` | `v-p1` |
| 3. MITM | `p3` | `evidencias\p3_mitm` | `v-p3` |
| 4. Firmas | `p4` | `evidencias\p4_firmas` | `v-p4-mitm`, `v-p4-legitima` |

Crear las carpetas y los archivos de trabajo (ejemplo para la prueba 1; repetir cambiando la carpeta):

```powershell
$P = "evidencias\p1_pago"
New-Item -ItemType Directory -Force "$P\originales", "$P\trabajo", "$P\cifrados", "$P\recuperados", "$P\logs" | Out-Null

# Archivos de prueba: uno de texto y uno binario
"Documento de prueba de la Actividad III" | Set-Content "$P\originales\documento.txt"
$bytes = New-Object byte[] 1048576; (New-Object Random 42).NextBytes($bytes)
[IO.File]::WriteAllBytes("$PWD\$P\originales\binario.bin", $bytes)

# La víctima trabaja sobre copias; los originales se reservan para comparar
Copy-Item "$P\originales\*" "$P\trabajo\"
```

> **Importante:** no usar `docker compose down -v` hasta terminar una prueba: `-v` borra el volumen con el registro y las claves del servidor.

## 4. Patrón común de cada prueba

Todas las pruebas siguen los mismos pasos. Abajo solo se indica lo que cambia.

```powershell
# a) Levantar los servicios de la prueba
docker compose -p p1 up --build -d servidor mitm

# b) Copiar la clave pública de firma del servidor a la víctima (canal de confianza)
docker compose -p p1 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\

# c) Ejecutar la víctima (registro, entrega de sV y cifrado)
python victima\victima.py cifrar --id v-p1 --puerto 5000 --entrada evidencias\p1_pago\trabajo --salida evidencias\p1_pago\cifrados

# d) Cerrar y reiniciar (paso 4)
docker compose -p p1 stop
docker compose -p p1 start

# e) Guardar las trazas
docker compose -p p1 logs servidor > evidencias\p1_pago\logs\servidor.log
```

> **Pendiente:** ajustar los comandos de `victima.py` (subcomandos y opciones) cuando el cliente definitivo esté terminado.

## 5. Las cuatro pruebas

### Prueba 1. Cifrado y pago (pasos 1–4, 5a y 6)

Patrón común con `-p p1`, víctima en el puerto `5000`. Después del reinicio:

```powershell
python victima\victima.py recuperar-pago --id v-p1 --puerto 5000 --entrada evidencias\p1_pago\cifrados --salida evidencias\p1_pago\recuperados
```

### Prueba 2. Investigación (paso 5b)

Usa una copia de los cifrados de la prueba 1, con el servidor apagado.

```powershell
docker compose -p p1 stop
New-Item -ItemType Directory -Force evidencias\p2_investigacion\cifrados, evidencias\p2_investigacion\recuperados | Out-Null
Copy-Item evidencias\p1_pago\cifrados\* evidencias\p2_investigacion\cifrados\

python investigacion\investigar.py --entrada evidencias\p2_investigacion\cifrados --salida evidencias\p2_investigacion\recuperados --mediciones evidencias\p2_investigacion\mediciones.csv
```

La investigación solo lee los archivos cifrados y sus metadatos. No accede a `servidor/datos`, a claves privadas ni a los resultados de la prueba 1.

### Prueba 3. MITM (M1–M6)

Patrón común con `-p p3`, pero la víctima se conecta al intermediario (`--puerto 5001`) con `--sin-firmas`. Al terminar, con víctima y servidor cerrados:

```powershell
docker compose -p p3 stop servidor
docker compose -p p3 logs mitm > evidencias\p3_mitm\logs\mitm.log
# Recuperación por el intermediario con la maestra interceptada (M6)
```

### Prueba 4. Firmas digitales

Patrón común con `-p p4`. Se ejecuta tres veces:

| Caso | Puerto | Resultado esperado |
|---|---|---|
| Sustitución de clave (`v-p4-mitm`) | `5001` | La víctima rechaza la clave y no envía la semilla |
| Firma propia del intermediario | `5001` | Rechazo: la clave de verificación no es la de confianza |
| Intercambio legítimo (`v-p4-legitima`) | `5000` | Cifrado, reinicio y recuperación por pago completos |

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
