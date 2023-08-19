#!/usr/bin/env pyhton

# pip3 install scapy-python3
import scapy.all as scapy
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser(
        prog='network_scanner',
        description='Returns the IP and MAC addresses of all devices connected to a specified network.',
        epilog='Part of EthicalHackingTools.'
    )
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP or IP range, use --help for more info.")
    elif not re.match(r"^\d+.\d+.\d+.\d+(/\d{1,2})*$", str(options.target)):
        parser.error("[-] Please specify a valid target, use --help for more info.")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Create a ethernet frame with broadcast MAC address as destination
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the arp and broadcast packets
    arp_request_broadcast = broadcast/arp_request

    # Send and receive function - returns answered packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for answer in answered_list:
        clients_list.append({"IP": answer[1].psrc, "MAC": answer[1].hwsrc})

    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["MAC"])


options = get_arguments()
# "192.168.64.1/24"
print_result(scan(options.target))
