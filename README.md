# SOCKS5 Proxy y Management Client

Este proyecto implementa un servidor SOCKS5 flexible y dos clientes:
- **socks5_client**: Cliente interactivo para probar el proxy SOCKS5 (con o sin autenticación).
- **mgmt_client**: Cliente para administrar el servidor (usuarios, estadísticas, etc.).

---
## ¿Como compilar?
make clean para limpiar los binario y ejecutables.

make all para compilar todo.

## ¿Como correr el proxy sockv5?
./bin/server/programa


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
./bin/client/socks5_client [proxy_host] [proxy_port] [username] [password]
```
- Si no se pasan argumentos, usa los valores por defecto.

### Ejemplo de uso
```sh
./bin/client/socks5_client 127.0.0.1 1080
```
- Menú interactivo:
  1. Autenticarse (opcional)
  2. Test HTTP (a httpbin.org)
  3. Request HTTP personalizado (host, puerto, path)
  4. Salir

- Puedes probar:
  - Dominios: `www.google.com`
  - IPv4: `8.8.8.8`
  - IPv6: `2001:4860:4860::8888`

---

## mgmt_client

### ¿Qué es?
Un cliente de administración para el protocolo de management del servidor. Permite:
- Autenticarse como administrador.
- Consultar estadísticas del servidor (conexiones, bytes transferidos, etc.).
- Listar, agregar, eliminar y cambiar contraseñas de usuarios.

### ¿Cómo funciona?
- Al iniciar, solicita autenticación obligatoria.
- Luego muestra un menú de comandos:
  1. Obtener estadísticas
  2. Listar usuarios
  3. Agregar usuario
  4. Eliminar usuario
  5. Cambiar contraseña de usuario
  6. Salir

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
- También puedes configurar el usuario y contraseña de admin mediante variables de entorno (ver documentación del servidor o código fuente para detalles).

---

## Requisitos
- Compilar con un compilador C estándar (gcc recomendado).
- El servidor debe estar corriendo y accesible en la IP/puerto configurados.

