#!/usr/bin/env python
import netfilterqueue
import subprocess
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if(scapy_packet.haslayer(scapy.DNSRR)):
        print(scapy_packet.show())
    packet.accept()


# subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0") # -I FORWARD for remote target hosts, -I OUTPUT & INPUT for current host
# subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0")

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

# subprocess.call("iptables --flush")
