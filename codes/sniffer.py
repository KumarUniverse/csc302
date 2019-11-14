#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
  pkt.show()
  print("Packet received.")

pkt = sniff(iface='eth1', filter='icmp',prn=print_pkt)
