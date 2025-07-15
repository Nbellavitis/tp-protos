# SOCKS5 Proxy y Management Client

Este proyecto implementa un servidor SOCKS5 flexible y dos clientes:
- **socks5_client**: Cliente interactivo para probar el proxy SOCKS5 (con o sin autenticación).
- **mgmt_client**: Cliente para administrar el servidor (usuarios, estadísticas, etc.).

---
## ¿Como compilar?
```sh
make clean   # Limpia binarios previos
make all     # sirve para compilar una versión más rápida del código ignorando flags de chequeo de memoria que puede ralentizar el código
make all BUILD=debug # sirve para hacer una validación del código y entender bien qué está pasando ante cualquier fallo del programa
```

## Ubicación de materiales y artefactos

- **Servidor:**  
  Ejecutable en `bin/server/socks5d`
- **Clientes:**  
  Ejecutables en `bin/client/` (`socks5_client`, `mgmt_client`).
- **Scripts de stress y pruebas:**  
  En la raíz del proyecto (`test.sh`, `test2.sh`, `test3.sh`).
- **Documentación y reportes:**  
  En la raíz (`README.md` e informe).

---


Los ejecutables se generan en:
- `bin/server/` para el servidor
- `bin/client/` para los clientes

---



## Ejemplo de estructura de carpetas tras compilar

```
tp-protos/
├── bin/
│   ├── server/
│   │   └── socks5d
│   └── client/
│       ├── socks5_client
│       └── mgmt_client
├── README.md
└── ...
```


## ¿Como correr el proxy sockv5?
./bin/server/socks5d


## socks5_client

### ¿Qué es?
Un cliente interactivo en C que permite:
- Conectarse a un proxy SOCKS5 (con o sin autenticación).
- Realizar peticiones HTTP a través del proxy.
- Probar dominios, IPv4 e IPv6.
- Cambiar entre modo autenticado y no autenticado en tiempo real.

### ¿Cómo funciona?
- Al iniciar, puedes elegir:
  - Autenticarse (usuario/contraseña) → el cliente solo ofrece el método USERPASS.
  - Usar el proxy sin autenticación → el cliente solo ofrece el método NO AUTH.
- Puedes cambiar de modo (log out/log in) desde el menú.
- Permite hacer peticiones HTTP básicas o personalizadas (host, puerto, path).
- Muestra advertencias si la conexión puede demorar (timeout).

### Ejecución
```sh
./bin/client/socks5_client [proxy_host] [proxy_port] 
```
- Si no se pasan argumentos, usa los valores por defecto.

### Ejemplo de uso
```sh
./bin/client/socks5_client 127.0.0.1 1080
```

---

## mgmt_client

### ¿Qué es?
Un cliente de administración para el protocolo de management del servidor. Permite:
- Autenticarse como administrador.
- Consultar estadísticas del servidor (conexiones, bytes transferidos, etc.).
- Listar, agregar, eliminar y cambiar contraseñas de usuarios.
- Consultar o modificar el tamaño del buffer
- Consultar o modificar el metodo de autenticacion actual
- Ver los logs de un usuario en especifico

### Ejecución
```sh
./bin/client/mgmt_client [mgmt_host] [mgmt_port]
```
- Si no se pasan argumentos, usa los valores por defecto.

### Ejemplo de uso
```sh
./bin/client/mgmt_client 127.0.0.1 9090
```

---

## Notas
- Ambos clientes son interactivos y muestran mensajes claros sobre el estado de la conexión.
- El cliente SOCKS5 permite alternar entre modos autenticado/no autenticado sin reiniciar.
- El cliente de management requiere autenticación para todos los comandos.

---

## Credenciales de administración
- El usuario administrador por defecto es:
  - **Usuario:** admin
  - **Contraseña:** admin123

- Puedes configurar el usuario y contraseña de admin mediante variables de entorno antes de ejecutar el servidor :
  ```sh
  export ADMIN_USERNAME=tuadmin
  export ADMIN_PASSWORD=tuclave
  ./bin/server/socks5d ...
  ```
---

## Requisitos
- Compilar con un compilador C estándar (gcc recomendado).
- El servidor debe estar corriendo y accesible en la IP/puerto configurados.

---

