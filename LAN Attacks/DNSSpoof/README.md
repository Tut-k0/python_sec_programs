# DNS Spoofer
I didn't test this much so it may not even really work lmao.

## Need some prerequistites.
```bash
sudo apt install libnetfilter-queue-dev
pip install netfilterqueue
```
### Explanation
To modify packets on the fly we need to create a queue for the packets
we receive and rescend. We will use netfilter queue for that. We need to either
run this command or have the script run it via subproccess.
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