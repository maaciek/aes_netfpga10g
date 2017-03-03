#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "/home/maciejt/NetFPGA-10G-live-master/tools/lib/nf10_lib.c"
int system(const char *string);
int main(int argc, char *argv[]){

	printf("-------------------------------------------------\n");
	printf(" reset on write (1bit) %i \t\n", regwrite(0x7A400018, 0x00000001));
	printf("-------------------------------------------------\n");
	printf(" reset on read (1bit) %i \t\n", regread(0x7A400018));
	printf("-------------------------------------------------\n");
	printf(" reset of write (1bit) to 0 %i \t\n", regwrite(0x7A400018, 0x00000000));
	printf("-------------------------------------------------\n");
	printf(" reset on read (1bit) %i \t\n", regread(0x7A400018));
	printf("-------------------------------------------------\n");

}
