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
    El DNS (Sistema de Nombres de Dominio) traduce nombres de dominio legibles (ej., google.com) a direcciones IP (ej., 172.217.160.142). El DNS Spoofing, también conocido como envenenamiento de caché DNS, ocurre cuando un atacante falsifica la respuesta de un servidor DNS a una petición de un cliente. Si la víctima intenta acceder a `bancofalso.com`, el atacante intercepta la petición DNS y le envía una respuesta falsa, apuntando `bancofalso.com` a una IP controlada por el atacante (por ejemplo, un sitio de phishing).
    Este ataque a menudo se combina con ARP Spoofing para asegurar que el tráfico DNS de la víctima pase por el atacante.

* **Características Esperadas del Script `DnsSpoofing.py` (a desarrollar):**
    * **Intercepción de Peticiones DNS:** Escucha el tráfico DNS de la red.
    * **Falsificación de Respuestas DNS:** Responde a peticiones DNS específicas con direcciones IP falsas controladas por el atacante.
    * **Configuración de Reglas de Spoofing:** Permite al usuario definir qué dominios falsificar y a qué IP redirigirlos.
    * Integración potencial con ARP Spoofing para asegurar la intercepción del tráfico DNS.

* **Tecnologías y Conceptos Clave:**
    * **Python 3.x**
    * **Librería `scapy`:** Creación y análisis de paquetes DNS.
    * Protocolo DNS.
    * Envenenamiento de Caché DNS.
    * Redirección de Tráfico.

---

### **3. HTTP Spoofing (Protocolo de Transferencia de Hipertexto)**

* **¿Cómo Funciona?**
    El HTTP Spoofing implica la manipulación del tráfico HTTP (no cifrado) que pasa a través del atacante. Una vez que el atacante ha establecido una posición MITM (por ejemplo, con ARP Spoofing), puede interceptar y modificar las peticiones o respuestas HTTP en tiempo real. Esto puede usarse para inyectar contenido (ej., scripts maliciosos, banners de phishing), redirigir a los usuarios a sitios maliciosos, o alterar la información que ven en sitios no seguros. Es una técnica potente para inyectar JavaScript para capturar credenciales o cookies.

* **Características Esperadas del Script `HttpSpoofing.py` (a desarrollar):**
    * **Redirección HTTP:** Redirige peticiones HTTP a URLs controladas por el atacante.
    * **Inyección de Contenido:** Inyecta código HTML o JavaScript en páginas web no cifradas.
    * **Filtros Personalizados:** Permite definir reglas para qué tipo de tráfico HTTP interceptar y modificar.
    * Monitoreo básico de peticiones/respuestas HTTP.

* **Tecnologías y Conceptos Clave:**
    * **Python 3.x**
    * **Librería `scapy` (o `NetfilterQueue` con `scapy` para un proxy transparente):** Intercepción y manipulación de paquetes.
    * Protocolo HTTP (headers, métodos, estados).
    * Inyección de código (HTML, JavaScript).
    * Ataques MITM a nivel de aplicación.

---

### 🚀 Tecnologías y Herramientas Utilizadas (Generales para la Suite)

* **Lenguaje de Programación:** Python 3.x
* **Librerías Python:**
    * `scapy`: Fundamental para la creación, envío, captura y análisis de paquetes de red.
    * `argparse`: Para el manejo de argumentos de línea de comandos en cada script.
    * `os`, `sys`, `signal`, `time`, `re` (para DNS/HTTP, si aplica): Para operaciones de sistema, manejo de señales, temporización y expresiones regulares.
* **Conceptos de Red y Seguridad:**
    * Protocolos TCP/IP (ARP, DNS, HTTP)
    * Ataques Man-in-the-Middle (MITM)
    * IP Forwarding (requiere habilitación manual en el sistema atacante)
    * Filtrado y manipulación de paquetes

### 🛠️ Pre-requisitos y Configuración General

1.  **Máquina Atacante:**
    * Un sistema basado en **Linux** (recomendado, ya que Scapy funciona mejor y el control de red es más directo).
    * Python 3.x instalado.
    * **Librerías Scapy y `dnspython` (si usas para DNS):**
        ```bash
        pip install scapy dnspython # dnspython es útil para DNS queries/responses
        ```
2.  **Habilitar IP Forwarding (en la máquina atacante):**
    * Para que el tráfico interceptado por ARP Spoofing (y por extensión, DNS/HTTP Spoofing) se reenvíe a su destino real, debes habilitar el reenvío de IP.
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

Para cada herramienta, deberás ejecutarla con los argumentos específicos.

1.  **ArpSpoofing.py:**
    ```bash
    sudo python3 ArpSpoofing.py -t [IP_OBJETIVO] -g [IP_GATEWAY]
    ```
    * Reemplaza `[IP_OBJETIVO]` con la dirección IP de la víctima.
    * Reemplaza `[IP_GATEWAY]` con la dirección IP del router/gateway.
    * Detén con `Ctrl+C` para restaurar las tablas ARP.

2.  **DnsSpoofing.py (Ejemplo - script a desarrollar):**
    ```bash
    sudo python3 DnsSpoofing.py --domain [DOMINIO_A_FALSIFICAR] --ip [IP_FALSA]
    ```
    * Este script debería funcionar junto con `ArpSpoofing.py` (en otra terminal) o si ya controlas el tráfico de alguna otra forma.

3.  **HttpSpoofing.py (Ejemplo - script a desarrollar):**
    ```bash
    sudo python3 HttpSpoofing.py --redirect-to [URL_MALICIOSA] --inject-js [URL_DE_JS_MALICIOSO]
    ```
    * Este script también requerirá que el tráfico HTTP pase por tu máquina (generalmente con ARP Spoofing).

### ⚠️ Advertencias y Consideraciones Éticas

* Estos proyectos están diseñados **exclusivamente con fines educativos y de investigación en ciberseguridad**.
* **Nunca uses estas herramientas contra sistemas o redes sin el permiso explícito y por escrito de sus propietarios.** Es ilegal y puede tener graves consecuencias.
* Los ataques de spoofing pueden interrumpir la conectividad de la red si no se manejan correctamente.
* El autor no se hace responsable del uso indebido de estas herramientas.

### 🗺️ Roadmap (Posibles Mejoras Futuras para la Suite)

* **Interfaz Unificada:** Un script principal que orchestre los diferentes tipos de spoofing.
* **Manejo de Firewall:** Configuración automática de reglas de `iptables` para reenviar o manipular tráfico.
* **Capacidades de Logging:** Registrar el tráfico o los eventos de spoofing.
* **Detección:** Implementar módulos para detectar ataques de spoofing en la red.
* **Integración de Sniffer:** Capturar y analizar el tráfico interceptado directamente desde las herramientas.

### ✉️ Contacto

[Zm0kSec]
www.linkedin.com/in/benedicto-palma-verdugo-094931301
