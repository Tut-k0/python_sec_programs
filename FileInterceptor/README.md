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