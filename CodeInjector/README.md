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