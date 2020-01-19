#!/usr/bin/env python

import scapy.all as scapy
import argparse


def scan(ip):
    # Creating arp request...
    arp_request = scapy.ARP(pdst=ip)

    # Creating ethernet frame for setting destination MAC....
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combining both packets...
    arp_request_broadcast = broadcast / arp_request

    # Sending and receiving requests...
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []

    # Iterating in the list...
    for element in answered_list:
        # Storing IP address and MAC Address...
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def print_result(result_list):
    print("_" * 45)
    print("IP\t\t\tMAC Address")
    print("-" * 45)

    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


# Taking arguments from commandline....
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", dest="target_ip", help="Target IP / Range IP")
options = parser.parse_args()
target = options.target_ip

print_result(scan(target))
