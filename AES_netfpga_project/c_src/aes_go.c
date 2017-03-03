#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "/home/maciejt/NetFPGA-10G-live-master/tools/lib/nf10_lib.c"
int system(const char *string);
int main(int argc, char *argv[]){
		printf("---------------- WRITE -----------------------\n");
		printf("-------------------------------------------------\n");
		printf(" AES enable (1bit) %i \t\n", regwrite(0x7A400014, 0x00000001));

		printf("---------------- READ -----------------------\n");
		printf("-------------------------------------------------\n");
		printf(" AES enable (1bit) = %8llx \t\n", regread(0x7A400014));
		printf("-------------------------------------------------\n");
}
