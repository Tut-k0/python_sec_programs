#!/usr/bin/env python3
import optparse
import scapy.layers.l2
import scapy.all


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Specify an IP or range to scan. Ex: 192.168.1.1/24")
    (options, meme) = parser.parse_args()  # Optparse might be overkill for this.
    if not options.target:
        parser.error("Please specify an IP or IP range to scan, use --help for more info.")
    return options


def scan(ip):  # scapy.all.ls(scapy.layers.l2.ARP()) is where we found our parameters.
    arp_request = scapy.layers.l2.ARP(pdst=ip)
    broadcast = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.layers.l2.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for element in answered:
        client = {"ip": element[1].psrc, "MAC": element[1].hwsrc}
        clients.append(client)
    return clients


def print_result(results):
    print("IP\t\t\tMAC Address\n---------------------------------------------------------")
    for client in results:
        print(client["ip"] + "\t\t" + client["MAC"])


args = get_arguments()
scan_result = scan(args.target)
print_result(scan_result)
