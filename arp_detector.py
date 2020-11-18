#!usr/bin/env/python

import scapy.all as scapy
import optparse


def get_arguments():
    #parser = argparse.ArgumentParser()
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interfaces", help="Interface to sniff to.")
    (option, argument) = parser.parse_args() # no arguments on argparser only option
    return option


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #only first element, second is [1] # add unanswered_list
    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)


def process_sniff_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack!")
        except IndexError:
            pass


sniff(get_arguments().interfaces)
