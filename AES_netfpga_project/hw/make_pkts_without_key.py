#!/usr/bin/env python-nf

from __future__ import with_statement

import os
import sys

script_dir = os.path.dirname( sys.argv[0] )
# Add path *relative to this script's location* of axitools module
sys.path.append( os.path.join( script_dir, '..','..','..','tools','scripts' ) )

# NB: axitools import must preceed any scapy imports
import axitools

from scapy.layers.all import Ether, IP, TCP


pkts=[]

TEST_VECTOR_DATA=('1EF2','1EF2','1EF2')
# A simple TCP/IP packet embedded in an Ethernet II frame
#for i in range(1):
#    pkt = (Ether(src='11:22:33:44:55:66', dst='77:88:99:aa:bb:cc')/
#           IP(src='192.168.1.1', dst='192.168.1.2')/
#           TCP()/
#           'AAAAAAAAAAA') ##'AAAAAAAAAAA'TEST_VECTOR_DATA.pop([i])
#    pkt.time        = (2e-6+i*(1e-8))*2
    # Set source network interface for DMA stream
#    pkt.tuser_sport = 1 << (i%4*2 + 1) # PCI ports are odd-numbered
#    pkts.append(pkt)
# PCI interface
#with open( os.path.join( script_dir, 'dma_0_stim.axi' ), 'w' ) as f:
#    axitools.axis_dump( pkts, f, 256, 1e-9 )
#with open( os.path.join( script_dir, 'dma_0_expected.axi' ), 'w' ) as f:
#    axitools.axis_dump( pkts*4, f, 256, 1e-9 )

# 10g interfaces
#for i in range(1):
    # replace source port
#    for pkt in pkts:
#        pkt.tuser_sport = 1 << (i*2) # physical ports are even-numbered
#    with open( os.path.join( script_dir, 'nf10_10g_interface_%d_stim.axi' % i ), 'w' ) as f:
#        axitools.axis_dump( pkts, f, 256, 1e-9 )
#    with open( os.path.join( script_dir, 'nf10_10g_interface_%d_expected.axi' % i ), 'w' ) as f:
#        axitools.axis_dump( pkts[0:2], f, 256, 1e-9 )
