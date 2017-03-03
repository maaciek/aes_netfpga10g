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
		printf("-------------------------------------------------\n");
		printf(" AES key enable (1bit) to 0 %i \t\n", regwrite(0x7A400010, 0x00000000));
		printf("-------------------------------------------------\n");
		printf(" encryption key part1 %i \t\n", regwrite(0x7A400000, 0x00000000));
		printf("-------------------------------------------------\n");
		printf(" encryption key part2 %i \t\n", regwrite(0x7A400004, 0x00000000));
		printf("-------------------------------------------------\n");
		printf(" encryption key part3 %i \t\n", regwrite(0x7A400008, 0x00000000));
		printf("-------------------------------------------------\n");
		printf(" encryption key part4 %i \t\n", regwrite(0x7A40000C, 0x00000000));
		printf("-------------------------------------------------\n");
		printf(" AES key enable (1bit) to 1 %i \t\n", regwrite(0x7A400010, 0x00000001));
		printf("-------------------------------------------------\n");
		printf("---------------- READ -----------------------\n");
		printf("-------------------------------------------------\n");
		printf(" AES enable (1bit) = %8llx \t\n", regread(0x7A400014));
		printf("-------------------------------------------------\n");
		printf(" AES key enable (1bit) = %8llx \t\n", regread(0x7A400010));
		printf("-------------------------------------------------\n");
		printf(" encryption key part1 = %8llx \t\n", regread(0x7A400000));
		printf("-------------------------------------------------\n");
		printf(" encryption key part2 = %8llx \t\n", regread(0x7A400004));
		printf("-------------------------------------------------\n");
		printf(" encryption key part3 = %8llx \t\n", regread(0x7A400008));
		printf("-------------------------------------------------\n");
		printf(" encryption key part4 = %8llx \t\n", regread(0x7A40000C));
		printf("-------------------------------------------------\n");
}
