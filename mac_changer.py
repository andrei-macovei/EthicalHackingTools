#!/usr/bin/env python

import subprocess
import argparse
import re


def get_arguments():
    parser = argparse.ArgumentParser(
        prog='mac_changer',
        description='Changes the MAC address of a specified network interface to a MAC address of your choice.',
        epilog='Part of EthicalHackingTools.'
    )

    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_argument("-m", "--mac", dest="new_mac", help="New MAC address")

    arguments = parser.parse_args()

    if not arguments.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not arguments.new_mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")

    if not(re.match(r"^\w\w:\w\w:\w\w:\w\w:\w\w:\w\w$", str(arguments.new_mac))):
        parser.error("[-] Please specify a correct new mac, using the format xx:xx:xx:xx:xx:xx")

    # Checks if provided interface exists
    try:
        ifconfig_res = str(subprocess.check_output(["ifconfig", arguments.interface]))
    except subprocess.CalledProcessError:
        parser.error("[-]Please provide an existing interface. You can check them using 'ifconfig' command.")

    return arguments


def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_res = str(subprocess.check_output(["ifconfig", interface]))
    mac_address_search_res = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_res)

    if mac_address_search_res:
        return mac_address_search_res.group(0)
    else:
        print("[-] Could not read MAC address.")


options = get_arguments()

current_mac = get_current_mac(options.interface)
print("Current MAC is " + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address successfully changed to " + current_mac)
else:
    print("[-] MAC address was not changed")
