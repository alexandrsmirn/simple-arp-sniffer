import socket
import struct
import binascii
import argparse
import re

def parse_oui():
    OUI = {}
    with open('oui.txt') as data:
        for line in data:
            try:
                mac, company = re.search(r'([0-9A-F]{6})\s+\(base 16\)\s+(.+)', line).groups()
                OUI[mac.lower()]=company
            except AttributeError:
                continue

    return OUI

parser = argparse.ArgumentParser(description="A simple ARP sniffer")
parser.add_argument("-i", dest='iface', default='wlp7s0')
args = parser.parse_args()

OUI = parse_oui()
sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
    raw_bytes, info = sniff_socket.recvfrom(65535)
    ether_type = info[1]

    #ethernet_data = struct.unpack("6s6s2s", raw_bytes[0:14])
    #ether_type = int.from_bytes(ethernet_data[2], 'big')

    if not info[0] == args.iface or not ether_type == 0x0806:
        continue

    print("Recieved ARP packet")
    arp_data = struct.unpack("2s2s1s1s2s6s4s6s4s", raw_bytes[14:42])

    opcode = int.from_bytes(arp_data[4], 'big')
    if opcode == 1:
        print("Packet type: request")
    else:
        print("Packet type: reply")

    sender_addr = binascii.hexlify(arp_data[5]).decode('utf-8')
    target_addr = binascii.hexlify(arp_data[7]).decode('utf-8')

    sender_vendor = OUI.get(sender_addr[:6], 'N/A: Unknown vendor')
    if target_addr == '000000000000':
        target_vendor = "N/A: MAC is unknown yet"
    else:
        target_vendor = OUI.get(target_addr[:6], 'N/A: Unknown vendor')
    
    print("Sender address (base 64):", sender_addr)
    print("Sender vendor:", sender_vendor)

    print("Target address (base 64):", target_addr)
    print("Target vendor:", target_vendor)

    print('\n')