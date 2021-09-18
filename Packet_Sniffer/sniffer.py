#!/usr/bin/env python3
import scapy.all
import scapy.layers.l2
from scapy.layers import http


#  prn is to specify a callback function.
def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=sniffed_packet)


def sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.all.Raw):
            print(packet[scapy.all.Raw].load)


sniff("eth0")
