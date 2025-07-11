# Network-Spoofing-Suite-Python

![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)
![Network Attacks](https://img.shields.io/badge/Category-Network_Attacks-red.svg)
![MITM](https://img.shields.io/badge/Attack-MITM-orange.svg)
![OS: Linux](https://img.shields.io/badge/OS-Linux-informational.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg) ---

### 📄 Descripción General del Proyecto

Este repositorio contiene una suite de herramientas de **Spoofing** implementadas en `Python3` utilizando librerías de manipulación de paquetes de red. Su propósito principal es **educar y demostrar** cómo se pueden explotar diversas vulnerabilidades a nivel de red para realizar ataques de "Man-in-the-Middle" (MITM).

A través de estos scripts, podrás comprender el funcionamiento de protocolos fundamentales como ARP, DNS y HTTP, identificar sus puntos débiles y aprender sobre técnicas ofensivas clave en ciberseguridad. Cada herramienta está diseñada con un enfoque educativo, explicando los principios subyacentes del ataque y cómo se logra la intercepción o la manipulación del tráfico.

### 💡 ¿Qué es el Spoofing en Redes? (Concepto Educativo)

El Spoofing (suplantación) en el contexto de redes es una técnica en la que un atacante se hace pasar por otro dispositivo o entidad confiable en una red. El objetivo es engañar a los dispositivos o usuarios para que envíen información al atacante o para que el atacante pueda monitorear o manipular el tráfico de red que no le debería corresponder. Es la base de muchos ataques de "Man-in-the-Middle" (MITM), donde el atacante se posiciona entre dos partes que se comunican.

Este repositorio explora tres tipos fundamentales de spoofing:

---

### **1. ARP Spoofing (Protocolo de Resolución de Direcciones)**

* **¿Cómo Funciona?**
    El Protocolo de Resolución de Direcciones (ARP) es crucial en redes locales (LAN) para traducir direcciones IP (lógicas) a direcciones MAC (físicas). Los dispositivos mantienen una "tabla ARP" con estas asociaciones. El ARP Spoofing explota la confianza ciega del protocolo ARP. El atacante envía paquetes ARP falsos a la víctima (diciéndole que la IP del router es la MAC del atacante) y al router (diciéndole que la IP de la víctima es la MAC del atacante). Esto envenena sus tablas ARP, haciendo que ambos dirijan su tráfico hacia el atacante, quien luego lo reenvía a su destino real (requiriendo **IP Forwarding** habilitado en la máquina atacante) para no interrumpir la conectividad mientras se monitorea o modifica el tráfico.

* **Características del Script `ArpSpoofing.py`:**
    * **Envenenamiento ARP Bidireccional:** Engaña tanto a la víctima como al router (gateway) para interceptar el tráfico.
    * **Detección Automática de MACs:** Obtiene las direcciones MAC reales del objetivo y del gateway utilizando peticiones ARP.
    * **Restauración de Tablas ARP (CRÍTICO):** Al detener el script (`Ctrl+C`), la herramienta envía paquetes ARP legítimos para restaurar las tablas ARP de la víctima y el router, devolviendo la conectividad normal a la red.
    * **Interfaz de Línea de Comandos (CLI):** Uso de `argparse` para especificar la IP objetivo y la IP del gateway como argumentos.
    * **Contador de Paquetes:** Muestra el número de paquetes ARP enviados en tiempo real.

* **Tecnologías y Conceptos Clave:**
    * **Python 3.x**
    * **Librería `scapy`:** Manipulación de paquetes de red.
    * Protocolo ARP, Direcciones IP/MAC.
    * Ataques Man-in-the-Middle (MITM).
    * IP Forwarding.

---

### **2. DNS Spoofing (Sistema de Nombres de Dominio)**

* **¿Cómo Funciona?**
    El DNS (Sistema de Nombres de Dominio) es el "directorio telefónico de Internet", traduciendo nombres de dominio legibles (ej., `google.com`) a direcciones IP (ej., `172.217.160.142`). Un ataque de **DNS Spoofing**, también conocido como envenenamiento de caché DNS, ocurre cuando un atacante falsifica la respuesta de un servidor DNS a una petición de un cliente.

    1.  **Intercepción:** El atacante, posicionado como "Man-in-the-Middle" (gracias a ARP Spoofing u otras técnicas), intercepta la petición DNS de la víctima.
    2.  **Falsificación:** Antes de que la petición llegue al servidor DNS legítimo, o antes de que su respuesta legítima llegue a la víctima, el atacante envía una respuesta DNS falsa a la víctima.
    3.  **Redirección:** Esta respuesta falsa le dice a la víctima que el nombre de dominio solicitado (ej., `bancofalso.com`) está asociado a una dirección IP controlada por el atacante (por ejemplo, la IP de un sitio de phishing o un servidor malicioso).
    4.  **Engaño:** La víctima, al recibir la respuesta DNS falsa primero (o creyéndola legítima), intenta conectarse a la IP maliciosa controlada por el atacante, en lugar de al sitio web original.

    Este ataque a menudo se combina con ARP Spoofing para asegurar que el tráfico DNS de la víctima pase por el atacante, permitiendo la intercepción necesaria.

* **Intercepción con NetfilterQueue e Iptables:**
    Para realizar DNS Spoofing, el atacante necesita una forma de interceptar los paquetes de red, inspeccionarlos y posiblemente modificarlos. En sistemas Linux, `iptables` y `NetfilterQueue` son herramientas poderosas para esto:
    * **`iptables`**: Es una utilidad de línea de comandos que permite configurar las reglas de firewall del kernel de Linux (Netfilter). Permite redirigir paquetes específicos a una "cola" (queue).
    * **`NetfilterQueue` (nfqueue)**: Es una interfaz de programación (API) que permite a las aplicaciones de espacio de usuario (como tu script Python) interactuar con los paquetes que `iptables` ha redirigido a una cola. Esto significa que puedes recibir paquetes en tu script, examinarlos, modificarlos y luego decidir si los aceptas (los dejas pasar), los deniegas (los descartas) o los inyectas de nuevo en la red modificados.

    **Reglas de `iptables` para Redirección (¡Necesitas `sudo` para esto!):**
    Para redirigir los paquetes de entrada (`INPUT`), salida (`OUTPUT`) y reenvío (`FORWARD`) al `NFQUEUE` con número de cola `0`:

    ```shell
    # Redirige los paquetes que entran a la máquina (si la víctima eres tú)
    iptables -I INPUT -j NFQUEUE --queue-num 0 

    # Redirige los paquetes que salen de la máquina (si la víctima eres tú)
    iptables -I OUTPUT -j NFQUEUE --queue-num 0 

    # Redirige los paquetes que se reenvían a través de la máquina (común en MITM)
    iptables -I FORWARD -j NFQUEUE --queue-num 0 

    # Asegura que la política de FORWARD sea ACCEPT para permitir el reenvío de tráfico
    # Esto es crucial si estás haciendo MITM y quieres que la víctima tenga internet
    iptables --policy FORWARD ACCEPT
    ```
    * **`-I` (Insert):** Inserta la regla al principio de la cadena.
    * **`-j NFQUEUE`:** Indica que el destino del paquete es `NFQUEUE`.
    * **`--queue-num 0`:** Especifica el número de cola al que se enviarán los paquetes. Tu script Python debe "escuchar" en este mismo número de cola.

    **Para Desactivar/Eliminar las Reglas de `iptables`:**
    Es vital limpiar las reglas de `iptables` después del ataque para restaurar la conectividad normal. Para ello, reemplaza `-I` con `-D` (Delete):

    ```shell
    # Eliminar reglas específicas
    iptables -D INPUT -j NFQUEUE --queue-num 0
    iptables -D OUTPUT -j NFQUEUE --queue-num 0
    iptables -D FORWARD -j NFQUEUE --queue-num 0

    # Restaurar la política FORWARD si la habías cambiado y no quieres que esté en ACCEPT
    # Ten cuidado si tu sistema requiere una política diferente por defecto.
    # iptables --policy FORWARD DROP 
    ```

* **Características del Script `DnsSpoofing.py`:**
    * **Intercepción Activa:** Captura peticiones DNS enviadas por el objetivo.
    * **Falsificación Selectiva:** Permite al atacante especificar qué dominios desea falsificar y a qué IP maliciosa deben redirigirse.
    * **Manipulación de Paquetes Scapy:** Utiliza `Scapy` para construir y modificar respuestas DNS de forma programática.
    * **Inyección de Paquetes Modificados:** Reenvía las respuestas DNS falsificadas a la víctima.
    * **Restauración de Reglas Iptables:** Incluye una función para limpiar las reglas de `iptables` al finalizar, restaurando la conectividad normal.

* **Tecnologías y Conceptos Clave:**
    * **Python 3.x**
    * **Librería `netfilterqueue`:** Interceptación de paquetes a nivel de kernel.
    * **Librería `scapy`:** Creación, edición y análisis de paquetes de red, especialmente DNS.
    * `iptables`: Configuración de reglas de firewall.
    * Protocolo DNS (peticiones `DNSRR` - DNS Resource Record).
    * Envenenamiento de Caché DNS.
    * MITM a nivel DNS.

---

### **3. HTTP Spoofing (Protocolo de Transferencia de Hipertexto)**

* **¿Cómo Funciona?**
    El HTTP Spoofing implica la manipulación del tráfico HTTP (no cifrado) que pasa a través del atacante. Una vez que el atacante ha establecido una posición MITM (por ejemplo, con ARP Spoofing), puede interceptar y modificar las peticiones o respuestas HTTP en tiempo real. Esto puede usarse para inyectar contenido (ej., scripts maliciosos, banners de phishing), redirigir a los usuarios a sitios maliciosos, o alterar la información que ven en sitios no seguros. Es una técnica potente para inyectar JavaScript para capturar credenciales o cookies.

    **Puntos Clave del Proceso:**
    1.  **Intercepción:** El tráfico HTTP (comúnmente en el puerto 80) es redirigido a la máquina del atacante (usando `iptables` y `netfilterqueue`, al igual que con DNS Spoofing).
    2.  **Inspección:** El script examina los paquetes para determinar si son peticiones (salientes) o respuestas (entrantes) HTTP.
    3.  **Modificación:**
        * **Peticiones:** Puede modificar cabeceras (ej., eliminar `Accept-Encoding` para asegurar respuestas no comprimidas y facilitar la inyección), o alterar la URL de la petición para redirigir al navegador.
        * **Respuestas:** Puede inyectar código (como JavaScript o HTML) en el cuerpo de la página web que recibe la víctima, o reemplazar texto dentro del contenido.
    4.  **Reenvío:** El paquete modificado se reenvía a su destino.

    **Importante:** Esta técnica solo funciona para tráfico **HTTP (no cifrado)**. El tráfico HTTPS (cifrado, puerto 443) no puede ser manipulado directamente con esta técnica sin un ataque de descifrado más complejo como SSL Stripping o falsificación de certificados.

* **Características del Script `HttpSpoofing.py`:**
    * **Intercepción de Tráfico HTTP:** Captura peticiones y respuestas HTTP utilizando `netfilterqueue` y `iptables`.
    * **Manipulación de Cabeceras HTTP:** Elimina la cabecera `Accept-Encoding` de las peticiones para prevenir la compresión de respuestas y facilitar la inyección de contenido.
    * **Inyección de Contenido en Tiempo Real:** Demuestra la capacidad de reemplazar texto o inyectar scripts (ej., `JavaScript` con un `alert()`) directamente en el cuerpo de las respuestas HTTP.
    * **Recalculado Automático de Checksums:** `Scapy` maneja la actualización de checksums IP y TCP después de la modificación del payload, asegurando que los paquetes sigan siendo válidos.
    * **Restauración de Reglas Iptables:** Incluye una función para limpiar las reglas de `iptables` al finalizar el script (`Ctrl+C`), restaurando la conectividad de red.

* **Tecnologías y Conceptos Clave:**
    * **Python 3.x**
    * **Librería `netfilterqueue`:** Interceptación de paquetes a nivel de kernel.
    * **Librería `scapy`:** Creación, edición y análisis de paquetes de red, incluyendo capas HTTP y TCP.
    * `iptables`: Configuración de reglas de firewall para redirigir tráfico.
    * Protocolo HTTP (peticiones GET/POST, respuestas, cabeceras, cuerpo).
    * Inyección de Código (HTML, JavaScript).
    * Ataques MITM a nivel de aplicación.
    * Expresiones Regulares (`re`).

---

### 🚀 Tecnologías y Herramientas Utilizadas (Generales para la Suite)

* **Lenguaje de Programación:** Python 3.x
* **Librerías Python:**
    * `scapy`: Fundamental para la creación, envío, captura y análisis de paquetes de red.
    * `netfilterqueue`: Para la intercepción de paquetes a nivel de kernel (especialmente para DNS y HTTP Spoofing).
    * `argparse`: Para el manejo de argumentos de línea de comandos en cada script.
    * `os`, `sys`, `signal`, `time`, `re` (para DNS/HTTP): Para operaciones de sistema, manejo de señales y temporización.
* **Conceptos de Red y Seguridad:**
    * Protocolos TCP/IP (ARP, DNS, HTTP)
    * Ataques Man-in-the-Middle (MITM)
    * IP Forwarding (requiere habilitación manual en el sistema atacante)
    * Filtrado y manipulación de paquetes

### 🛠️ Pre-requisitos y Configuración General

1.  **Máquina Atacante:**
    * Un sistema basado en **Linux** (recomendado, ya que Scapy y NetfilterQueue funcionan mejor y el control de red es más directo).
    * Python 3.x instalado.
    * **Librerías Python (Instalación General):**
        ```bash
        sudo apt-get update
        sudo apt-get install build-essential python3-dev libnetfilter-queue-dev
        pip3 install scapy netfilterqueue --break-system-packages
        ```
        * **Nota:** Para entornos de desarrollo más limpios, considera usar [entornos virtuales](https://docs.python.org/3/library/venv.html).
2.  **Habilitar IP Forwarding (en la máquina atacante):**
    * Para que el tráfico interceptado (esencial para MITM) se reenvíe a su destino real, debes habilitar el reenvío de IP.
    * Ejecuta el siguiente comando en tu terminal (se requiere `sudo`):
        ```bash
        sudo sysctl -w net.ipv4.ip_forward=1
        ```
    * Para deshabilitarlo después (o si reinicias):
        ```bash
        sudo sysctl -w net.ipv4.ip_forward=0
        ```
    * Para que sea persistente a los reinicios, edita `/etc/sysctl.conf` y descomenta/añade la línea `net.ipv4.ip_forward = 1`.

### ⚙️ Cómo Usar las Herramientas (Ejemplos)

Para cada herramienta, deberás ejecutarla con los argumentos específicos. **Todos los scripts requieren privilegios de root (`sudo`).**

1.  **`ArpSpoofing.py`:**
    ```bash
    sudo python3 ArpSpoofing.py -t [IP_OBJETIVO] -g [IP_GATEWAY]
    ```
    * Reemplaza `[IP_OBJETIVO]` con la dirección IP de la víctima que quieres engañar.
    * Reemplaza `[IP_GATEWAY]` con la dirección IP de tu router o gateway de red.
    * **Detener el Ataque:** Presiona `Ctrl+C`. El script restaurará las tablas ARP antes de salir.

2.  **`DnsSpoofing.py`:**
    ```bash
    sudo python3 DnsSpoofing.py -s [DOMINIO_A_FALSIFICAR_1]:[IP_FALSA_1] -s [DOMINIO_A_FALSIFICAR_2]:[IP_FALSA_2]
    ```
    * **Ejemplo:** `sudo python3 DnsSpoofing.py -s google.com:192.168.1.100 -s facebook.com:192.168.1.101`
    * Este script debe ejecutarse **después de que el tráfico ya esté pasando por tu máquina** (generalmente usando `ArpSpoofing.py` en otra terminal).
    * **Detener el Ataque:** Presiona `Ctrl+C`. El script eliminará automáticamente las reglas de `iptables`.

3.  **`HttpSpoofing.py`:**
    Este script te permite interceptar y manipular el tráfico HTTP (no cifrado) que fluye a través de tu máquina, posicionado como un Man-in-the-Middle. Puedes modificar cabeceras, inyectar contenido (como JavaScript malicioso) o cambiar el texto en las respuestas web.

    **Sintaxis (Requiere `sudo`):**

    ```bash
    sudo python3 HttpSpoofing.py
    ```

    **Flujo para un Ataque MITM Completo con HTTP Spoofing:**

    1.  **Habilita IP Forwarding** en tu máquina atacante (ver sección de `Pre-requisitos y Configuración General` en el `README.md` principal).
    2.  **Inicia el ARP Spoofing:** En una terminal, ejecuta `ArpSpoofing.py` para redirigir el tráfico del objetivo (y del router) a tu máquina.
        ```bash
        sudo python3 ArpSpoofing.py -t [IP_OBJETIVO] -g [IP_GATEWAY]
        ```
    3.  **Inicia el HTTP Spoofing:** En OTRA terminal, ejecuta `HttpSpoofing.py`.
        ```bash
        sudo python3 HttpSpoofing.py
        ```
        * **Importante:** Este script solo afectará al tráfico HTTP (no cifrado, puerto 80). El tráfico HTTPS (cifrado, puerto 443) no puede ser manipulado directamente con esta técnica sin un ataque más complejo como SSL Stripping o falsificación de certificados.
    4.  **Prueba desde la Máquina Objetivo:**
        * Navega a un sitio web **HTTP** (no HTTPS). Por ejemplo, un sitio de prueba HTTP como `http://testphp.vulnweb.com/` o `http://http.badssl.com/`.
        * Deberías ver la modificación del contenido (ej. "Hacked by ZmkBlacK ToT") o el script inyectado ejecutarse en el navegador del objetivo.

    **Detener el Ataque:**

    * Presiona `Ctrl+C` en la terminal donde se ejecuta `HttpSpoofing.py`. El script eliminará automáticamente las reglas de `iptables` que añadió.
    * Luego, detén también el script `ArpSpoofing.py` (si lo estabas usando) para restaurar completamente la conectividad de la red.

### ⚠️ Advertencias y Consideraciones Éticas

* Estos proyectos están diseñados **exclusivamente con fines educativos y de investigación en ciberseguridad**.
* **Nunca uses estas herramientas contra sistemas o redes sin el permiso explícito y por escrito de sus propietarios.** Es ilegal y puede tener graves consecuencias.
* Los ataques de spoofing pueden interrumpir la conectividad de la red si no se manejan correctamente (especialmente la restauración de las tablas ARP y las reglas de `iptables`).
* El autor no se hace responsable del uso indebido de estas herramientas.

### 🗺️ Roadmap (Posibles Mejoras Futuras para la Suite)

* **Interfaz Unificada:** Un script principal que orchestre los diferentes tipos de spoofing.
* **Manejo Automático de Firewall:** Configuración más inteligente de reglas de `iptables`.
* **Capacidades de Logging:** Registrar el tráfico o los eventos de spoofing.
* **Detección:** Implementar módulos para detectar ataques de spoofing en la red.
* **Integración de Sniffer:** Capturar y analizar el tráfico interceptado directamente desde las herramientas.

### ✉️ Contacto

[TZm0kSec]
www.linkedin.com/in/benedicto-palma-verdugo-094931301
