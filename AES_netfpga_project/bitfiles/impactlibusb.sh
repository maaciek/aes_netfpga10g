#!/bin/bash
source /opt/Xilinx/13.4/ISE_DS/settings64.sh
(cd /opt/Xilinx/14.4/ISE_DS/ISE/bin/lin64
#LD_PRELOAD=./libusb-driver.so # inoffizieller Treiber
XIL_IMPACT_USE_LIBUSB=1
./impact)
