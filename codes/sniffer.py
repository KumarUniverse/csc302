#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
  pkt.show()
  print("Packet received.")

pkt = sniff(filter='icmp',prn=print_pkt)
