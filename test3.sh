#!/bin/bash

SERVER=127.0.0.1
PORT=1080
CONNECTIONS=1018
DURATION=30  # segundos

PIDS=()
echo "Abriendo $CONNECTIONS conexiones TCP al proxy $SERVER:$PORT durante $DURATION segundos..."

for i in $(seq 1 $CONNECTIONS); do
    nc $SERVER $PORT </dev/null &
    PIDS+=($!)
    sleep 0.01
done

# Espera un poco para que todas se abran
sleep 2

# Cuenta cuántos procesos nc están vivos (conexiones abiertas)
MAX_OPEN=$(ps -p "${PIDS[@]}" --no-headers | wc -l)
echo "Conexiones abiertas simultáneamente: $MAX_OPEN"

echo "Esperando $DURATION segundos..."
sleep $DURATION

echo "Cerrando conexiones..."
for pid in "${PIDS[@]}"; do
    kill $pid 2>/dev/null
done

echo "Test finalizado."