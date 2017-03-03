#!/usr/bin/env python-nf



from __future__ import with_statement

from optparse import OptionParser
import os
import sys

script_dir = os.path.dirname( sys.argv[0] )
# Add path *relative to this script's location* of axitools module
sys.path.append( os.path.join( script_dir, '..','..','..','tools','scripts' ) )

# NB: axitools import must preceed any scapy imports
import axitools
import crypto_axitools

from scapy.layers.all import Ether, IP, TCP

parser=OptionParser()

parser.add_option("-k","--key",dest="key",help="Encryption key")
(options,args)=parser.parse_args()


key=int(options.key,16)

pkts=[]
# A simple TCP/IP packet embedded in an Ethernet II frame
for i in range(1):
    pkt = (Ether(src='11:22:33:44:55:66', dst='77:88:99:aa:bb:cc')/
           IP(src='192.168.1.1', dst='192.168.1.2')/
#           TCP()/  #TCP is not used in this design
           'Hello, NetFPGA-10G!')
    pkt.time        = 2e-6+i*(1e-8) #give enough time for register configuration
    # Set source network interface for DMA stream
    pkt.tuser_sport = 1 << (i%4*2 + 1) # PCI ports are odd-numbered
    pkts.append(pkt)

save_payload=pkts[0].payload.payload
# PCI interface
with open( os.path.join( script_dir, 'dma_0_stim.axi' ), 'w' ) as f:
    axitools.axis_dump( pkts, f, 256, 1e-9 )
with open( os.path.join( script_dir, 'dma_0_expected.axi' ), 'w' ) as f:
    for i in range(1):
       for pkt in pkts:
           pkt.payload.payload=save_payload
       crypto_axitools.axis_dump( pkts, f, 256, 1e-9,key)

for pkt in pkts:
   pkt.payload.payload=save_payload

# 10g interfaces
for i in range(1):
    # replace source port
    for pkt in pkts:
        pkt.tuser_sport = 1 << (i*2) # physical ports are even-numbered
    with open( os.path.join( script_dir, 'nf10_10g_interface_%d_stim.axi' % i ), 'w' ) as f:
       axitools.axis_dump( pkts, f, 256, 1e-9 )
for i in range(1):
    for pkt in pkts:
        pkt.payload.payload=save_payload
    with open( os.path.join( script_dir, 'nf10_10g_interface_%d_expected.axi' % i ), 'w' ) as f:
        crypto_axitools.axis_dump( pkts[0:2], f, 256, 1e-9, key)
