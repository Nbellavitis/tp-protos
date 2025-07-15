#!/bin/bash

# CONFIGURACIÓN
CONNECTIONS=5000          # Total de conexiones a lanzar
CONCURRENCY=600           # Número de conexiones concurrentes
SERVER=127.0.0.1         # Dirección del proxy
PORT=1080                 # Puerto del proxy

# Lista de 10 endpoints válidos
URLS=(
  "https://speed.hetzner.de/10MB.bin"
  "https://speed.hetzner.de/1MB.bin"
  "https://speed.hetzner.de/100MB.bin"
  "https://example.com"
  "https://www.google.com"
  "https://www.cloudflare.com"
  "https://www.wikipedia.org"
  "https://www.gnu.org"
  "https://www.kernel.org"
  "https://www.mozilla.org"
)

# Convertir el array a string para exportarlo
URLS_JOINED=$(IFS='|'; echo "${URLS[*]}")

echo "Iniciando stress test con $CONNECTIONS conexiones al proxy $SERVER:$PORT..."
echo "Usando $CONCURRENCY conexiones concurrentes."
echo "Dividiendo entre ${#URLS[@]} endpoints HTTPS."
echo ""

# Crear archivo de log
LOGFILE="stress_results_$(date +%H%M%S).log"
> "$LOGFILE"

# Función que realiza una única conexión
single_connection() {
    ID=$1

    # Reconstruir el array de URLs
    IFS='|' read -r -a URL_ARRAY <<< "$URLS_JOINED"
    IDX=$(( (ID - 1) % ${#URL_ARRAY[@]} ))
    URL="${URL_ARRAY[$IDX]}"

    START=$(date +%s%3N)

    # Ejecutar curl con manejo de errores y tiempo
    RESULT=$(curl -x "socks5h://$SERVER:$PORT" \
        --connect-timeout 5 --max-time 10 \
        -w "%{http_code}" -o /dev/null -s "$URL" 2>&1)

    CODE="$RESULT"
    END=$(date +%s%3N)
    ELAPSED=$((END - START))

    echo "[$ID] URL: $URL | Código: $CODE | Tiempo: ${ELAPSED}ms" >> "$LOGFILE"
}

export -f single_connection
export SERVER PORT LOGFILE URLS_JOINED

# Lanzar las conexiones
seq 1 $CONNECTIONS | xargs -n1 -P$CONCURRENCY -I{} bash -c 'sleep $(awk "BEGIN {print rand()*0.3}"); single_connection {}'

# Mostrar resumen
echo ""
echo "Stress test completado. Resultados guardados en $LOGFILE"

echo ""
echo "Resumen de códigos HTTP:"
grep -o "Código: [0-9]*" "$LOGFILE" | sort | uniq -c

echo ""
echo "Promedio de tiempo de respuesta:"
awk '{sum+=$NF; count++} END {if (count>0) printf("%.2f ms\n", sum/count); else print "No se midió tiempo"}' "$LOGFILE"