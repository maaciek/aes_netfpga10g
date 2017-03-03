

`timescale 1ns / 10ps

module wrapper_aes_cipher_top(clk, rst, kld, done, /*done2,*/ key, text_in, text_out /*, text_out2*/ );

input		clk, rst;
input		kld;
output		done;
//output		done2;
input	[127:0]	key;
input	[127:0]	text_in;
output	[127:0]	text_out;
//output	[127:0]	text_out2;


aes_cipher_top u0(
	.clk(		clk		),
	.rst(		rst		),
	.ld(		kld		),
	.done(		done		),
	.key(		key		),
	.text_in(	text_in		),
	.text_out(	text_out	)
	);

//aes_inv_cipher_top u1(
//	.clk(		clk		),
//	.rst(		rst		),
//	.kld(		kld		),
//	.ld(		done		),
//	.done(		done2		),
//	.key(		key		),
//	.text_in(	text_out	),
//	.text_out(	text_out2	)
//	);
	
	endmodule