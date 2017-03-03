#!/bin/env python

from NFTest import *
import random
import sys
from scapy.layers.all import Ether

phy0loop4 = ('../connections/conn', ['nf0', 'nf1'])

nftest_init(sim_loop = ['nf0', 'nf1'], hw_config = [phy0loop4])
nftest_start()

# set parameters
DA = "11:11:11:11:11:11"
SA = "22:22:22:22:22:22"
TTL = 64
DST_IP = "192.168.1.1"
SRC_IP = "192.168.0.1"
nextHopMAC = "dd:55:dd:66:dd:77"
NUM_PKTS = 1
pkt = [[], [], [], [], [], [], [], [], [], []]

pkt[0] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"000000000000000000000000000000000000D8CAECE0BDF40A12540D0A4296A472C2412199493F11CF353EACA4D302F4311E".decode("hex"))
pkt[1] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"000000000000000000000000000000000000bd8cc040d202c864782b698f271acfa357d652f18793422411ac8704c93b9ebd".decode("hex"))
pkt[2] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"000000000000000000000000000000000000a9dbeeb9c28e60bb3fee809b9187522976e74969209f5bb87e7e76d60272baca".decode("hex"))
pkt[3] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"0000000000000000000000000000000000000508b1780821fe4dd8e9ab281d4853c5969f6de07d7aaa56bbff1a2b5f173131".decode("hex"))
pkt[4] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"000000000000000000000000000000000000c0b1d73535c96c44dd9cf2781e1b36c244e2f669757bb3b2a2e024837e6d24e6".decode("hex"))
pkt[5] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"00000000000000000000000000000000000085f9f877dbdedd9cf3097ba9fc8283abe900d2f9a218a50fb8aa264dc72d9615".decode("hex"))
pkt[6] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"0000000000000000000000000000000000001b2a403832c05ad14fc32c8a20beb2c9381384106cb034c1761b9d0d06b33805".decode("hex"))
pkt[7] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"000000000000000000000000000000000000bff2e28ab83783d2f8f491b6f47358cead38fb02739dc2f89217b532e8aa1022".decode("hex"))
pkt[8] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"000000000000000000000000000000000000716cf1d0d99c35b6dbc5846f20bbfe9437b447df93f7ee119d85bd0ba6917b55".decode("hex"))
pkt[9] = (Ether(src='dd:bb:cc:dd:ee:ff', dst='00:ca:fe:00:dd:01')/
"0000000000000000000000000000000000003376d3c710a95ea8b2dae993b5b265e26b83cadf8483f6ac96613294d9e521f2".decode("hex"))

## test0 ## 1E31F402D3A4AC3E35CF113F49992141 * C272A496420A0D54120AF4BDE0ECCAD8 = D4BC020FFF5C51C674F37A3A33A264BC ## test0 ##
## test1 ## A3CF1A278F692B7864C802D240C08CBD * BD9E3BC90487AC1124429387F152D657 = D1AC3350CDD618E5D4364CB90984479F ## test1 ##
## test2 ## 295287919B80EE3FBB608EC2B9EEDBA9 * CABA7202D6767E7EB85B9F206949E776 = 61E9643312E6DE916C747C58A1D19809 ## test2 ##
## test3 ## C553481D28ABE9D84DFE210878B10805 * 3131175F2B1AFFBB56AA7A7DE06D9F96 = 543302A0DC8BF97451152F2C46E15C9A ## test3 ##
## test4 ## C2361B1E78F29CDD446CC93535D7B1C0 * E6246D7E8324E0A2B2B37B7569F6E244 = F58C045E19C11B9297F91A65D177FF06 ## test4 ##
## test5 ## AB8382FCA97B09F39CDDDEDB77F8F985 * 15962DC74D26AAB80FA518A2F9D200E9 = 423E9764CDFB78414470BF716EF99ABE ## test5 ##
## test6 ## C9B2BE208A2CC34FD15AC03238402A1B * 0538B3060D9D1B76C134B06C10841338 = A43537D6C6E83911EEE0B07BA498E057 ## test6 ##
## test7 ## CE5873F4B691F4F8D28337B88AE2F2BF * 2210AAE832B51792F8C29D7302FB38AD = 92B7B834176BE2B783614ACEC7916E1F ## test7 ##
## test8 ## 94FEBB206F84C5DBB6359CD9D0F16C71 * 557B91A60BBD859D11EEF793DF47B437 = C42105587E35F4F38E416BABF9134E15 ## test8 ##
## test9 ## E265B2B593E9DAB2A85EA910C7D37633 * F221E5D994326196ACF68384DFCA836B = D13B2EEB8F598BBD39466A6C877E79A8 ## test9 ##

print "Sending now: "
pkts = []
totalPktLengths = [0]
# send NUM_PKTS from ports nf0...nf3
for i in range(NUM_PKTS):
    sys.stdout.write('\r'+str(i))
    sys.stdout.flush()

    pkts.append(pkt[i])
    totalPktLengths[0] += len(pkts[i])
    nftest_send_phy('nf' + str(0), pkts[i])
    nftest_expect_phy('nf' + str(1), pkts[i])

print ""
print "Packet entries in the register:"
hwReg.readReg("0x5a000008")

print "HASH:"
hwReg.readReg("0x79200014")
hwReg.readReg("0x79200010")
hwReg.readReg("0x7920000c")
hwReg.readReg("0x79200008")

nftest_finish()
