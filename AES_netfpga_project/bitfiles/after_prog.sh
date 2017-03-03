#!/bin/bash

cd ../../../tools/scripts/
./pci_save_restore.sh restore dma
cd -
lspci -d *:4244 -vxx
cd ../sw/host/driver
rmmod nf10.ko
make
insmod nf10.ko
cd -
ifconfig nf0 down
ifconfig nf1 down
ifconfig nf2 down
ifconfig nf3 down
ifconfig nf0 up
ifconfig nf1 up
ifconfig nf2 up
ifconfig nf3 up
