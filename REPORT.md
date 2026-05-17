# Reporte Técnico — CVE-2026-31431 (Copy Fail)

## 1. Bug raíz

La existencia del bug está en `crypto/algif_aead.c` y, más concretamente, en `_aead_recvmsg()`. La cuestión radica en que `aead_request_set_crypt()` toma `rsgl_src` como buffer tanto de origen como de destino, realizando la operación criptográfica in-place: en resumen, cuando el kernel procesa una AEAD, escribe el resultado sobre la misma área de memoria que contiene los datos de entrada.

## 2. Por qué el write a dst[assoclen + cryptlen] es peligroso

Al realizar una operación AEAD in-place, el kernel escribe en `dst[assoclen + cryptlen]`, que se sitúa justo después del texto cifrado, lo cual puede ser problemático si esas páginas pertenecen al page cache de un archivo que está almacenado en disco. El page cache es una capa de memoria utilizada por el kernel para mantener copias de archivos en memoria, permitiendo solicitudes rápidas cuando se necesita acceder a las vistas de los mismos. Por lo tanto, si esas páginas pertenecen a un binario setuid, por ejemplo, `/usr/bin/su`, el kernel estaría escribiendo bytes controlados por el atacante sobre el propio código ejecutable en memoria, sin haber pasado por el sistema de archivos y sin necesidad de permisos de escritura sobre el archivo.

## 3. Por qué el exploit es "stealthy"

El exploit es discreto porque no cambia el archivo en disco, sino que aprovecha que el kernel puede usar copy-on-write (COW) para la cache de páginas: el kernel mapea los mismos páginas físicas en memoria cuando un proceso empieza a leer un archivo en disco. Esto se hace usando la abordaje COW para trasladar las páginas físicas del archivo del disco a la memoria compartida (page cache). Cuando se cambia directamente en esas páginas físicamente con el exploit, la página física queda con la modificación de memoria pero el archivo en disco no ha cambiado. Herramientas de análisis forense (de verificación de la integridad de archivos, como `sha256sum` o sistemas IDS basados en hashes) no comprobarían los cambios porque el archivo en disco es el mismo.

## 4. Conexión con conceptos de clase

Page cache: El sistema operativo guarda las páginas de los archivos en la memoria RAM para evitar que cualquier acceso a disco vuelva a realizarse por segunda vez. El exploit escribirá en ese cache las páginas directamente, de forma que no corrompa la versión de disco sino la versión que existía en RAM.
 
chmod y setuid: Un binario con el bit setuid le dice a UNIX que se ejecute como si lo hiciera el propietario (root) y no el usuario que lanza el binario. En este caso, el exploit corrompe `/usr/bin/su` en el page cache y, al ser lanzado por un usuario, en lugar del código original ejecutará un shellcode que solamente llamará `setuid(0)` y ejecutará `/bin/sh`.

Inodes: Un inodo es el almacenamiento de los metadatos de un archivo y de los permisos del mismo y de los punteros hacia los bloques de información. El page cache hace el mapeo de esos bloques en memoria. Al modificar las páginas de cache sin pasar por el inodo ni por el sistema de archivos, se bypasea completamente el sistema de permisos.

## 5. Cómo múltiples cambios razonables crean un bug grave

Este CVE es un claro ejemplo de lo que ocurre cuando razonables optimizaciones individuales se combinan y juntas conllevan la creación de una vulnerabilidad muy seria. También fue en 2017 cuando se introdujo una optimización legítima, en la que, mediante la concatenación de listas de scatter-gather, se lograba realizar la operación AEAD in-place y por tanto mejorar el rendimiento al reducir las copias de memoria, lo cual puede considerarse una decisión técnicamente correcta.
Pero claro, esta optimización asumía que las páginas del buffer de destino eran siempre páginas privadas de su proceso, sin considerar el caso de que las páginas en las que iba a escribirse pudiesen ser parte del page cache de archivos que estaban mapeados en memoria. Unido al hecho de que AF_ALG permitía a procesos sin privilegios realizar operaciones criptográficas del kernel, así como al hecho de que `splice()` podía llegar a apuntar hacia páginas del page cache de binarios setuid nos lleva a que tres características independientes y razonables juntas generan una primitiva de escritura arbitraria en la memoria del kernel.
La lección es que la seguridad no debe evaluarse en componentes aislados; las interacciones entre subsistemas pueden llevar a la creación de vulnerabilidades que no estaban presentes en ningún componente en sí.
