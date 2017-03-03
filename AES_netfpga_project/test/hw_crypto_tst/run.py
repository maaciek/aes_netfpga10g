#!/bin/env python

from NFTest import *
import random
import sys

phy0loop4 = ('../connections/conn', ['nf0', 'nf1', 'nf2', 'nf3'])

nftest_init(sim_loop = ['nf0', 'nf1', 'nf2', 'nf3'], hw_config = [phy0loop4])
nftest_start()

# set parameters
DA = "00:ca:fe:00:dd:01"
SA = "dd:bb:cc:dd:ee:ff"
TTL = 64
DST_IP = "192.168.1.1"
SRC_IP = "192.168.0.1"
nextHopMAC = "dd:55:dd:66:dd:77"
NUM_PKTS = 1

print "Sending now: "
pkts = [[], [], [], []]
totalPktLengths = [0,0,0,0]
# send NUM_PKTS from ports nf0...nf3
for i in range(NUM_PKTS):
    sys.stdout.write('\r'+str(i))
    sys.stdout.flush()
    port=1
    for port in range(1):
#	DA = "00:ca:fe:00:00:%02x"%port
        pkts[port].append(make_IP_pkt(dst_MAC=DA, src_MAC=SA, dst_IP=DST_IP,
                             src_IP=SRC_IP, TTL=TTL,
 #                            pkt_len=random.randint(60,1514)))
pkt_len=200))
        totalPktLengths[port] += len(pkts[port][i])
        nftest_send_dma('nf' + str(0), pkts[0][i])
        nftest_expect_dma('nf' + str(1), pkts[0][i])
print ""
print "Packet entries in the register:"
hwReg.readReg("0x5a000008")

nftest_finish()
