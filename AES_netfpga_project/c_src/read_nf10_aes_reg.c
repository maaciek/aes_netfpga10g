#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "/home/maciejt/NetFPGA-10G-live-master/tools/lib/nf10_lib.c"
int system(const char *string);
int ref_counter = 0;
int identical = 1;
int main(){
	

	uint32_t 	ro_regs_signals,
				total_pkt_counter_maxi,
				total_pkt_counter_out,
				total_pkt_counter;

				
	uint32_t 	ro_regs_signals_d1, 
				total_pkt_counter_maxi_d1,
				total_pkt_counter_out_d1,
				total_pkt_counter_d1;
				
	//int num_of_frame = 1;
	//int k = 0;



	
	while(1) {
		//sleep(8);
		ro_regs_signals  = regread(0x7A40001C);
		
		total_pkt_counter_out = regread(0x7A400020);
		total_pkt_counter_maxi = regread(0x7A400024);
		total_pkt_counter = regread(0x7A400028);

	
	
		if (   (ro_regs_signals != ro_regs_signals_d1) 
			|| (total_pkt_counter != total_pkt_counter_d1)
			|| (total_pkt_counter_maxi != total_pkt_counter_maxi_d1)
			|| (total_pkt_counter_out != total_pkt_counter_out_d1) ) 
		{
	
			printf("------------------- REFRESH %i ------------------\n", ref_counter );
			printf("--------------- CONTROL REGS READ ---------------\n");
			printf("-------------------------------------------------\n");
			
			printf(" total_pkt_counter = %8lld \t\n", total_pkt_counter);
			printf("-------------------------------------------------\n");
			printf(" total_pkt_counter_maxi = %8lld \t\n", total_pkt_counter_maxi);
			printf("-------------------------------------------------\n");
			printf(" total_pkt_counter_out = %8lld \t\n", total_pkt_counter_out);
			printf("-------------------------------------------------\n");
			
			printf(" in_fifo_empty = %8lld \t\n", ((ro_regs_signals << 14) >> 31) );
			printf("-------------------------------------------------\n");
			printf(" out_fifo_empty = %8lld \t\n", ((ro_regs_signals << 16) >> 31) );
			printf("-------------------------------------------------\n");
			printf(" maxi_fifo_empty = %8lld \t\n", ((ro_regs_signals << 18) >> 31) );
			printf("-------------------------------------------------\n");

			printf(" in_fifo_nearly_full = %8lld \t\n", ((ro_regs_signals << 15) >> 31));
			printf("-------------------------------------------------\n");
			printf(" out_fifo_nearly_full = %8lld \t\n", ((ro_regs_signals << 17) >> 31) );
			printf("-------------------------------------------------\n");			
			printf(" maxi_fifo_nearly_full = %8lld \t\n", ((ro_regs_signals << 19) >> 31) );
			printf("-------------------------------------------------\n");

			printf(" tlast_end_state = %8lld \t\n", ((ro_regs_signals << 24) >> 28) );
			printf("-------------------------------------------------\n");
			printf(" tlast_end_state_maxi = %8lld \t\n", ((ro_regs_signals << 20) >> 28) );
			printf("-------------------------------------------------\n");

			printf(" AES_count = %8lld \t\n", (ro_regs_signals >> 25));
			printf("-------------------------------------------------\n");
			printf(" AES_done_cnt = %8lld \t\n", ((ro_regs_signals << 7) >> 25)) ;
			printf("-------------------------------------------------\n");
			
			printf(" state = %8lld \t\n", ((ro_regs_signals << 28) >> 28) );
			printf("-------------------------------------------------\n");


			printf("*************************************************\n");
			ref_counter ++;
			if (ref_counter == 100000) ref_counter = 0;
		
		}
		
		
		ro_regs_signals_d1 = ro_regs_signals;
		total_pkt_counter_d1 = total_pkt_counter;
		total_pkt_counter_maxi_d1 = total_pkt_counter_maxi;
		total_pkt_counter_out_d1 = total_pkt_counter_out;

		identical = 1;

	}
}
