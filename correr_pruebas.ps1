# correr_pruebas.ps1
# Ejecuta las cuatro pruebas de la Actividad III y guarda todo en evidencias\.
# Uso (desde la carpeta que tiene docker-compose.yml, con Docker Desktop abierto):
#   .\.venv\Scripts\Activate.ps1
#   .\correr_pruebas.ps1
# OJO: borra las evidencias y los volúmenes anteriores de p1, p3 y p4.

$ErrorActionPreference = "Continue"

# Todo en UTF-8: consola, salida de Python y archivos de evidencia.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

function Ejecutar($salida, $comando) {
    # cmd /c une stdout y stderr antes de llegar a PowerShell: así no aparecen
    # los avisos rojos NativeCommandError y la evidencia queda limpia en UTF-8.
    $lineas = cmd /c "$comando 2>&1"
    $lineas | Set-Content -Encoding UTF8 $salida
    $lineas
}

function Guardar-Log($proyecto, $servicio, $salida) {
    cmd /c "docker compose -p $proyecto logs --no-log-prefix $servicio 2>&1" | Set-Content -Encoding UTF8 $salida
}

function Paso($texto) { Write-Host "`n==== $texto ====" -ForegroundColor Cyan }

function Victima($proyecto, $salida) {
    # Ejecuta la víctima en su contenedor y guarda su salida en un archivo.
    Ejecutar $salida "docker compose -p $proyecto run --rm victima $($args -join ' ')"
}

function Comparar($P) {
    Get-ChildItem "$P\originales" | ForEach-Object {
        $o = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        $r = (Get-FileHash "$P\recuperados\$($_.Name)" -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        "{0,-20} {1}" -f $_.Name, $(if ($o -eq $r) { "IDENTICO" } else { "DISTINTO o FALTA" })
    } | Tee-Object -Variable lineas
    $lineas | Set-Content -Encoding UTF8 "$P\comparacion.txt"
}

function Confianza($proyecto, $id) {
    # Canal de confianza víctima -> servidor
    docker compose -p $proyecto run --rm victima preparar --id $id
    docker compose -p $proyecto cp "victima\datos\$id\clave_firma_publica.pem" "servidor:/app/servidor/datos/confianza_victimas/$id.pem"
}

# ---------------------------------------------------------------- limpieza
Paso "Limpieza"
foreach ($p in "p1", "p3", "p4") { docker compose -p $p down -v 2>$null }
Remove-Item -Recurse -Force evidencias -ErrorAction SilentlyContinue
Get-ChildItem victima\datos -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Remove-Item -Force victima\datos\clave_firma_publica.pem -ErrorAction SilentlyContinue
Remove-Item -Force mitm\datos\*.json -ErrorAction SilentlyContinue
# Datos viejos del servidor en el anfitrión: no deben quedar (ni entrar en la imagen)
Get-ChildItem servidor\datos -Exclude .gitkeep -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

# ---------------------------------------------------------------- preparación
Paso "Pruebas unitarias"
New-Item -ItemType Directory -Force evidencias | Out-Null
Ejecutar evidencias\pruebas_unitarias.txt "python -m unittest pruebas.test_firmas pruebas.test_autenticacion_victima -v"

Paso "Archivos de trabajo"
foreach ($P in "evidencias\p1_pago", "evidencias\p3_mitm", "evidencias\p4_firmas") {
    New-Item -ItemType Directory -Force "$P\originales", "$P\trabajo", "$P\logs" | Out-Null
    "Documento de prueba de la Actividad III" | Set-Content "$P\originales\documento.txt"
    $bytes = New-Object byte[] 1048576; (New-Object Random 42).NextBytes($bytes)
    [IO.File]::WriteAllBytes("$PWD\$P\originales\binario.bin", $bytes)
    Copy-Item "$P\originales\*" "$P\trabajo\"
}

# ---------------------------------------------------------------- prueba 1
Paso "Prueba 1: cifrado y pago"
$L = "evidencias\p1_pago\logs"
docker compose -p p1 --profile cli build --no-cache
docker compose -p p1 up -d servidor mitm
Start-Sleep 8
docker compose -p p1 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
Confianza p1 v-p1
Victima p1 "$L\victima_cifrar.txt" cifrar --id v-p1 --host servidor --entrada evidencias/p1_pago/trabajo --salida evidencias/p1_pago/cifrados
docker compose -p p1 stop
docker compose -p p1 start servidor
Start-Sleep 5
Victima p1 "$L\victima_pago.txt" recuperar-pago --id v-p1 --host servidor --entrada evidencias/p1_pago/cifrados --salida evidencias/p1_pago/recuperados
Guardar-Log p1 servidor "$L\servidor.log"
docker compose -p p1 stop
Comparar "evidencias\p1_pago"

# ---------------------------------------------------------------- prueba 2
Paso "Prueba 2: investigación (servidor apagado)"
$P = "evidencias\p2_investigacion"
New-Item -ItemType Directory -Force "$P\cifrados" | Out-Null
Copy-Item evidencias\p1_pago\cifrados\* "$P\cifrados\"
Copy-Item evidencias\p1_pago\originales $P -Recurse
Ejecutar "$P\salida.txt" "python investigacion\investigar.py --entrada $P\cifrados --salida $P\recuperados --mediciones $P\mediciones.csv"
Comparar $P

# ---------------------------------------------------------------- prueba 3
Paso "Prueba 3: MITM"
$L = "evidencias\p3_mitm\logs"
docker compose -p p3 --profile cli build
docker compose -p p3 up -d servidor mitm
Start-Sleep 8
docker compose -p p3 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
Confianza p3 v-p3
Victima p3 "$L\victima_cifrar.txt" cifrar --id v-p3 --host mitm --puerto 5001 --sin-firmas --entrada evidencias/p3_mitm/trabajo --salida evidencias/p3_mitm/cifrados
Guardar-Log p3 servidor "$L\servidor.log"
Guardar-Log p3 mitm "$L\mitm.log"
docker compose -p p3 stop          # M5: víctima y servidor cerrados; M6 con el servidor apagado
Ejecutar "$L\mitm_descifrar.txt" "python mitm\mitm.py descifrar --id v-p3 --entrada evidencias\p3_mitm\cifrados --salida evidencias\p3_mitm\recuperados"
Comparar "evidencias\p3_mitm"

# ---------------------------------------------------------------- prueba 4
Paso "Prueba 4: firmas digitales"
$L = "evidencias\p4_firmas\logs"
docker compose -p p4 --profile cli build
docker compose -p p4 up -d servidor mitm
Start-Sleep 8
docker compose -p p4 cp servidor:/app/servidor/datos/clave_firma_publica.pem victima\datos\
foreach ($ID in "v-p4-mitm", "v-p4-firma-mitm", "v-p4-pkv", "v-p4-legitima") { Confianza p4 $ID }

Paso "Caso 1: sustitución de pkS (debe rechazar)"
Victima p4 "$L\victima_caso1.txt" cifrar --id v-p4-mitm --host mitm --puerto 5001 --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados_caso1
Guardar-Log p4 mitm "$L\mitm_caso1.log"

Paso "Caso 2: firma propia del intermediario (debe rechazar)"
$env:MITM_FIRMAR_PKM = "1"; docker compose -p p4 up -d --force-recreate mitm; Remove-Item Env:MITM_FIRMAR_PKM
Start-Sleep 8
Victima p4 "$L\victima_caso2.txt" cifrar --id v-p4-firma-mitm --host mitm --puerto 5001 --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados_caso2
Guardar-Log p4 mitm "$L\mitm_caso2.log"

Paso "Caso 3: sustitución de pkV (el servidor debe rechazar)"
$env:MITM_SUSTITUIR_PKV = "1"; docker compose -p p4 up -d --force-recreate mitm; Remove-Item Env:MITM_SUSTITUIR_PKV
Start-Sleep 8
Victima p4 "$L\victima_caso3.txt" cifrar --id v-p4-pkv --host mitm --puerto 5001 --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados_caso3
Guardar-Log p4 mitm "$L\mitm_caso3.log"

Paso "Caso 4: intercambio legítimo, reinicio y pago (debe completar)"
Victima p4 "$L\victima_caso4_cifrar.txt" cifrar --id v-p4-legitima --host servidor --entrada evidencias/p4_firmas/trabajo --salida evidencias/p4_firmas/cifrados
docker compose -p p4 stop
docker compose -p p4 start servidor
Start-Sleep 5
Victima p4 "$L\victima_caso4_pago.txt" recuperar-pago --id v-p4-legitima --host servidor --entrada evidencias/p4_firmas/cifrados --salida evidencias/p4_firmas/recuperados
Guardar-Log p4 servidor "$L\servidor.log"
docker compose -p p4 stop
Comparar "evidencias\p4_firmas"

Paso "Listo. Revise la carpeta evidencias\"
Get-ChildItem -Recurse evidencias -Filter comparacion.txt | ForEach-Object { "--- $($_.Directory.Name)"; Get-Content $_.FullName }
