#!/bin/bash

################################################################################
#
#  NetFPGA-10G http://www.netfpga.org
#
#  File:
#        impact_run.sh
#
#  Author:
#        Jong HAN
#  
#  Date : 23 April 2013
#
#  Description:
#     This scripts are to load a bit file.
#     Copy impact_run.sh, impac_fpga.cmd.template or impact_fpga_cpld.template,
#     pci_save_restore.sh to a directory of bitfile in each project directory.
#     Then, run
#     $./impact_run.sh <bitfile.bit> (and <cpld.jed> if it is necessary).
#     The scripts remove nf10 kernel, program FPGA, restore PCIe configuration,
#     and load nf10 kernel.
#
#
###############################################################################

xilinxtool=`echo $XILINX`

rm -rf impact_cpld.cmd
rm -rf impact.cmd

if [ -z $xilinxtool ]; then
	echo
	echo 'Setup Xilinx tools.'
	echo
	exit 1
fi

PATH=$XILINX/bin/lin64:$XILINX/../../ISE_DS/common/bin/lin64:$PATH

export PATH

if [ -z $1 ]; then
	echo
	echo 'Nothing input for bit file.'
	echo
	echo './impact_run.sh <bitfile_name.bit> for loading a bit file only.' 
	echo
	echo './impact_run.sh <bitfile_name.bit> <cpld.jed> for loading bit and cpld files.'
	exit 1
fi

if [ -e "$1" -a -e "$2" ]; then
	sed s:CPLDFILE_NAME_HERE:$2: <impact_fpga_cpld.cmd.template > impact_cpld.cmd
	sed s:BITFILE_NAME_HERE:$1: <impact_cpld.cmd > impact.cmd
elif [ -e "$1" -a -z "$2" ]; then
	sed s:BITFILE_NAME_HERE:$1: <impact_fpga.cmd.template > impact.cmd
else
	echo
	echo $1 not found
	echo
	exit 1 
fi

#Remove nf10 kernel driver.
nfdriver=`lsmod | grep nf10`

if [ -n "$nfdriver" ]; then
	rmmod ../../reference_nic/sw/host/driver/nf10.ko
fi

#Program FPGA
impact -batch impact.cmd

#Restore PCIe configuration
./pci_save_restore.sh restore dma

#Load nf10 kernel driver.
insmod ../../reference_nic/sw/host/driver/nf10.ko

rm -rf impact_cpld.cmd
rm -rf impact.cmd
