#!/usr/in/env pyhton

import argparse
import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Create an ethernet frame with broadcast MAC address as destination
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send and receive function
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # return MAC address of given IP
    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        # check if the source MAC from the ARP request is the same as the actual MAC of the source IP
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("\r[+] Discrepancy detected at " + str(time.ctime()) +
                      ". You may be under and ARP spoofing attack!", end="")
        except IndexError:
            pass


def get_arguments():
    parser = argparse.ArgumentParser(
        prog='arpspoof_detector',
        description='Detect the patterns specific to an ARP spoofing attack',
        epilog='Part of EthicalHackingTools.'
    )
    parser.add_argument("-i", "--interface", dest="interface", help="Target interface to sniff", default="eth0",
                        required=False)

    options = parser.parse_args()
    return options


arguments = get_arguments()
sniff(arguments.interface)
