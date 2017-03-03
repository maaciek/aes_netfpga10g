

`timescale 1ns / 10ps

module wrapper_aes_cipher_top(clk, rst, kld, done, key, text_in, text_in_0, text_out_0, text_out_1, text_out_2, text_out_3, text_out_4, text_out_5, text_out_6, text_out_7, text_out_8, text_out_9, text_out_10, text_out_11, text_out_12, text_out_13, text_out_14, text_out_15, text_out_16, text_out_17, text_out_18, text_out_19, text_out_20, text_out_21, text_out_22, text_out_23, text_out_24 );

input		clk, rst;
input [12 : 0] kld;
output wire [24 : 0] done;
input	[127:0]	key;
input [255:0] text_in;
output wire [127: 0] text_out_1, text_out_2, text_out_3, text_out_4, text_out_5, text_out_6, text_out_7, text_out_8, text_out_9, text_out_10, text_out_11, text_out_12, text_out_13, text_out_14, text_out_15, text_out_16, text_out_17, text_out_18, text_out_19, text_out_20, text_out_21, text_out_22, text_out_23, text_out_24;
input [127:0] text_in_0;
output wire [127:0] text_out_0;


	aes_cipher_top
		aes_cipher_top_0
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[0]), 
		 .done 		(done[0]),
		 .key		(key),
		 .text_in	(text_in_0),
		 .text_out	(text_out_0) 

		);
		
	aes_cipher_top
		aes_cipher_top_1
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[1]), 
		 .done 		(done[1]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_1) 

		);

	aes_cipher_top
		aes_cipher_top_2
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[1]), 
		 .done 		(done[2]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_2) 

		);
		
	aes_cipher_top
		aes_cipher_top_3
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[2]), 
		 .done 		(done[3]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_3) 

		);

	aes_cipher_top
		aes_cipher_top_4
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[2]), 
		 .done 		(done[4]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_4) 

		);

	aes_cipher_top
		aes_cipher_top_5
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[3]), 
		 .done 		(done[5]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_5) 

		);

	aes_cipher_top
		aes_cipher_top_6
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[3]), 
		 .done 		(done[6]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_6) 

		);


	aes_cipher_top
		aes_cipher_top_7
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[4]), 
		 .done 		(done[7]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_7) 

		);

	aes_cipher_top
		aes_cipher_top_8
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[4]), 
		 .done 		(done[8]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_8) 

		);
	aes_cipher_top		
		aes_cipher_top_9
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[5]), 
		 .done 		(done[9]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_9) 

		);

	aes_cipher_top
		aes_cipher_top_10
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[5]), 
		 .done 		(done[10]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_10) 

		);
		
	aes_cipher_top		
		aes_cipher_top_11
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[6]), 
		 .done 		(done[11]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_11) 

		);

	aes_cipher_top
		aes_cipher_top_12
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[6]), 
		 .done 		(done[12]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_12) 

		);
		
	aes_cipher_top
		aes_cipher_top_13
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[7]), 
		 .done 		(done[13]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_13) 

		);

	aes_cipher_top
		aes_cipher_top_14
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[7]), 
		 .done 		(done[14]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_14) 

		);
		
	aes_cipher_top
		aes_cipher_top_15
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[8]), 
		 .done 		(done[15]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_15) 

		);

	aes_cipher_top
		aes_cipher_top_16
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[8]), 
		 .done 		(done[16]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_16) 

		);

	aes_cipher_top
		aes_cipher_top_17
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[9]), 
		 .done 		(done[17]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_17) 

		);

	aes_cipher_top
		aes_cipher_top_18
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[9]), 
		 .done 		(done[18]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_18) 

		);


	aes_cipher_top
		aes_cipher_top_19
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[10]), 
		 .done 		(done[19]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_19) 

		);

	aes_cipher_top
		aes_cipher_top_20
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[10]), 
		 .done 		(done[20]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_20) 

		);
	aes_cipher_top		
		aes_cipher_top_21
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[11]), 
		 .done 		(done[21]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_21) 

		);

	aes_cipher_top
		aes_cipher_top_22
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[11]), 
		 .done 		(done[22]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_22) 

		);
		
	aes_cipher_top		
		aes_cipher_top_23
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[12]), 
		 .done 		(done[23]),
		 .key		(key),
		 .text_in	(text_in[127:0]),
		 .text_out	(text_out_23) 

		);

	aes_cipher_top
		aes_cipher_top_24
		(
		 .clk		(clk),
		 .rst		(rst),
		 .ld		(kld[12]), 
		 .done 		(done[24]),
		 .key		(key),
		 .text_in	(text_in[255:128]),
		 .text_out	(text_out_24) 

		);

	endmodule
