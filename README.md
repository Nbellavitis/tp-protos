# SOCKS5 Proxy y Management Client

Este proyecto implementa un servidor SOCKS5 flexible y dos clientes:
- **socks5_client**: Cliente interactivo para probar el proxy SOCKS5 (con o sin autenticación).
- **mgmt_client**: Cliente para administrar el servidor (usuarios, estadísticas, etc.).

---

## Requisitos y dependencias
- Compilador C estándar (gcc recomendado)
- make
- curl (para los scripts de stress)

---

## ¿Cómo compilar?
```sh
make clean   # Limpia binarios previos
make all     # Compila una versión rápida (sin flags de chequeo de memoria)
make all BUILD=debug # Compila en modo debug para validación y análisis de fallos
```

---

## Estructura de carpetas tras compilar
```
tp-protos/
├── bin/
│   ├── server/
│   │   └── socks5d
│   └── client/
│       ├── socks5_client
│       └── mgmt_client
├── test.sh
├── test2.sh
├── test3.sh
├── README.md
└── ...
```

---

## Ubicación de materiales y artefactos
- **Servidor:**  Ejecutable en `bin/server/socks5d`
- **Clientes:**  Ejecutables en `bin/client/` (`socks5_client`, `mgmt_client`)
- **Scripts de stress y pruebas:**  En la raíz del proyecto (`test.sh`, `test2.sh`, `test3.sh`)
- **Documentación y reportes:**  En la raíz (`README.md`, informe)

---

## ¿Cómo correr el proxy SOCKS5?
```sh
./bin/server/socks5d [opciones]
```
- Ejemplo: `./bin/server/socks5d -l 0.0.0.0 -p 1080`
- Opciones disponibles: ver documentación o `./bin/server/socks5d -h`

---

## socks5_client
### ¿Qué es?
Un cliente interactivo en C que permite:
- Conectarse a un proxy SOCKS5 (con o sin autenticación)
- Realizar peticiones HTTP a través del proxy
- Probar dominios, IPv4 e IPv6
- Cambiar entre modo autenticado y no autenticado en tiempo real

### ¿Cómo funciona?
- Al iniciar, puedes elegir:
  - Autenticarse (usuario/contraseña) → el cliente solo ofrece el método USERPASS
  - Usar el proxy sin autenticación → el cliente solo ofrece el método NO AUTH
- Puedes cambiar de modo (log out/log in) desde el menú
- Permite hacer peticiones HTTP básicas o personalizadas (host, puerto, path)
- Muestra advertencias si la conexión puede demorar (timeout)

### Ejecución
```sh
./bin/client/socks5_client [proxy_host] [proxy_port]
```
- Si no se pasan argumentos, usa los valores por defecto

### Ejemplo de uso
```sh
./bin/client/socks5_client 127.0.0.1 1080
```

---

## mgmt_client
### ¿Qué es?
Un cliente de administración para el protocolo de management del servidor. Permite:
- Autenticarse como administrador
- Consultar estadísticas del servidor (conexiones, bytes transferidos, etc.)
- Listar, agregar, eliminar y cambiar contraseñas de usuarios
- Consultar o modificar el tamaño del buffer
- Consultar o modificar el método de autenticación actual
- Ver los logs de un usuario en específico

### Ejecución
```sh
./bin/client/mgmt_client [mgmt_host] [mgmt_port]
```
- Si no se pasan argumentos, usa los valores por defecto

### Ejemplo de uso
```sh
./bin/client/mgmt_client 127.0.0.1 9090
```

---

## Scripts de stress
```sh
./test.sh
./test2.sh
./test3.sh
```

---

## Credenciales de administración y variables de entorno
- El usuario administrador por defecto es:
  - **Usuario:** admin
  - **Contraseña:** admin123
- Puedes configurar el usuario y contraseña de admin mediante variables de entorno antes de ejecutar el servidor:
  ```sh
  export ADMIN_USERNAME=tuadmin
  export ADMIN_PASSWORD=tuclave
  ./bin/server/socks5d ...
  ```

---

## Notas
- Ambos clientes son interactivos y muestran mensajes claros sobre el estado de la conexión
- El cliente SOCKS5 permite alternar entre modos autenticado/no autenticado sin reiniciar
- El cliente de management requiere autenticación para todos los comandos
- El servidor debe estar corriendo y accesible en la IP/puerto configurados

---


