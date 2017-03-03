/////////////////////////////////////////////////////
//
// 	Module: nf10_aes.v
//  Project: 128bit AES for IIP
//  Author: Maciej Tota 
//	Email:  maciek.tota(AT)gmail.com
//  Description: Performs encryption on data in packets. This module
//  uses 24x AES 128bit key module to encrypt data.
//
//  The first 512 bits of a packet are not touched (ETHERNET and IP Header + 240 data).
//
/////////////////////////////////////////////////////
`timescale 1ns/1ps

`uselib lib=unisims_ver
`uselib lib=proc_common_v3_00_a

module nf10_aes
#(
	
	parameter C_FAMILY = "virtex5",
	
	// Master AXI Stream Data Width
	parameter C_M_AXIS_DATA_WIDTH=256,
	parameter C_S_AXIS_DATA_WIDTH=256,
	parameter C_M_AXIS_TUSER_WIDTH=128,
	parameter C_S_AXIS_TUSER_WIDTH=128,
	parameter NUM_QUEUES=1,
	parameter UDP_REG_SRC_WIDTH=2,
	
	
	// AXI Registers Data Width
	parameter C_S_AXI_DATA_WIDTH    = 32,          
	parameter C_S_AXI_ADDR_WIDTH    = 32,          
	parameter C_USE_WSTRB           = 0,
	parameter C_DPHASE_TIMEOUT      = 0,
	parameter C_BASEADDR            = 32'hFFFFFFFF,
	parameter C_HIGHADDR            = 32'h00000000,
	parameter C_S_AXI_ACLK_FREQ_HZ  = 100
	)
	(
	// Part 1: System side signals
	// Global Ports
	input axi_aclk,
	input axi_resetn,
	
	// Master Stream Ports (interface to data path)
	output reg [C_M_AXIS_DATA_WIDTH - 1:0] m_axis_tdata,
	output reg [((C_M_AXIS_DATA_WIDTH / 8)) - 1:0] m_axis_tstrb,
	output reg [C_M_AXIS_TUSER_WIDTH-1:0] m_axis_tuser,
	output reg m_axis_tvalid,
	input  m_axis_tready,
	output reg m_axis_tlast,
	
	// Slave Stream Ports (interface to input arbiter)
	input [C_S_AXIS_DATA_WIDTH - 1:0] s_axis_tdata,
	input [((C_S_AXIS_DATA_WIDTH / 8)) - 1:0] s_axis_tstrb,
	input [C_S_AXIS_TUSER_WIDTH-1:0] s_axis_tuser,
	input  s_axis_tvalid,
	output s_axis_tready,
	input  s_axis_tlast,
	
	
	// Signals for AXI_IP and IF_REG (Added for debug purposes)
	// Slave AXI Ports
	input                                     S_AXI_ACLK,
	input                                     S_AXI_ARESETN,
	input      [C_S_AXI_ADDR_WIDTH-1 : 0]     S_AXI_AWADDR,
	input                                     S_AXI_AWVALID,
	input      [C_S_AXI_DATA_WIDTH-1 : 0]     S_AXI_WDATA,
	input      [C_S_AXI_DATA_WIDTH/8-1 : 0]   S_AXI_WSTRB,
	input                                     S_AXI_WVALID,
	input                                     S_AXI_BREADY,
	input      [C_S_AXI_ADDR_WIDTH-1 : 0]     S_AXI_ARADDR,
	input                                     S_AXI_ARVALID,
	input                                     S_AXI_RREADY,
	output                                    S_AXI_ARREADY,
	output     [C_S_AXI_DATA_WIDTH-1 : 0]     S_AXI_RDATA,
	output     [1 : 0]                        S_AXI_RRESP,
	output                                    S_AXI_RVALID,
	output                                    S_AXI_WREADY,
	output     [1 :0]                         S_AXI_BRESP,
	output                                    S_AXI_BVALID,
	output                                    S_AXI_AWREADY

);

//------------------ Internal Parameter-------------------------
	//Number of FMS states
	localparam NUM_STATES = 4;
	localparam AES_INIT = 0;
	localparam S_AES_1 = 1;
	localparam S_AES_2 = 2;
	localparam S_AES_3 = 3;
	localparam S_AES_4 = 4;
	localparam S_AES_5 = 5;
	localparam S_AES_6 = 6;
	localparam S_AES_7 = 7;
	localparam S_AES_8 = 8;
	localparam S_AES_9 = 9;
	localparam S_AES_10 = 10;
	localparam S_AES_11 = 11;
	localparam S_AES_12 = 12;
	localparam BYPASS = 13;
	localparam ETH_IP_HDR = 14;
	
	
	reg [NUM_STATES-1:0]             state;
	reg [NUM_STATES-1:0]             state_next;
	
	reg [NUM_STATES-1:0]             state_maxi;
	reg [NUM_STATES-1:0]             state_maxi_next;
	
	reg [NUM_STATES-1:0]             state_out;
	reg [NUM_STATES-1:0]             state_out_next;


	//-----------------INPUT FIFO---------------------////
	reg										in_fifo_rd_en;
	wire [C_S_AXIS_TUSER_WIDTH-1:0]			in_fifo_ctrl_dout;
	wire [C_S_AXIS_DATA_WIDTH-1:0]			in_fifo_data_dout;
	wire [C_S_AXIS_DATA_WIDTH-1:0]			tstrb_extended;
	wire [(C_S_AXIS_DATA_WIDTH / 8)- 1:0]	in_fifo_tstrb_dout;
	wire									in_fifo_tlast_dout;
	wire									in_fifo_nearly_full;
	wire									in_fifo_empty;
   
	//-----------------OUTPUT FIFO---------------------////
	/// inputs ///
	reg  [C_S_AXIS_TUSER_WIDTH-1:0]			out_fifo_tuser;
	reg [C_S_AXIS_DATA_WIDTH-1:0]			out_fifo_data;
	reg  [(C_S_AXIS_DATA_WIDTH / 8)- 1:0]	out_fifo_tstrb;
	reg										out_fifo_tlast;
	reg										out_fifo_tvalid; // write flag to output fifo
	reg										out_fifo_rd_en;  // read flag from output fifo
	/// outputs ///
	wire [C_S_AXIS_TUSER_WIDTH-1:0]			out_fifo_ctrl_dout;
	wire [C_S_AXIS_DATA_WIDTH-1:0]			out_fifo_data_dout;
	wire [(C_S_AXIS_DATA_WIDTH / 8)- 1:0]	out_fifo_tstrb_dout;
	wire									out_fifo_tlast_dout;
	wire									out_fifo_nearly_full;
	wire									out_fifo_empty;	

	//-----------------MAXI FIFO---------------------////
	/// inputs ///
	reg  [C_S_AXIS_TUSER_WIDTH-1:0]			maxi_fifo_tuser;
	reg [C_S_AXIS_DATA_WIDTH-1:0]			maxi_fifo_data;
	reg  [(C_S_AXIS_DATA_WIDTH / 8)- 1:0]	maxi_fifo_tstrb;
	reg										maxi_fifo_tlast;
	reg										maxi_fifo_tvalid; // write flag to maxi output fifo
	reg										maxi_fifo_rd_en;  // read flag from maxi output fifo
	/// outputs ///
	wire [C_S_AXIS_TUSER_WIDTH-1:0]			maxi_fifo_ctrl_dout;
	wire [C_S_AXIS_DATA_WIDTH-1:0]			maxi_fifo_data_dout;
	wire [(C_S_AXIS_DATA_WIDTH / 8)- 1:0]	maxi_fifo_tstrb_dout;
	wire									maxi_fifo_tlast_dout;
	wire									maxi_fifo_nearly_full;
	wire									maxi_fifo_empty;	

// register related signals

    wire                                            Bus2IP_Clk;
    wire                                            Bus2IP_Resetn;
    wire     [C_S_AXI_ADDR_WIDTH-1 : 0]             Bus2IP_Addr;
    wire     [0:0]                                  Bus2IP_CS;
    wire                                            Bus2IP_RNW;
    wire     [C_S_AXI_DATA_WIDTH-1 : 0]             Bus2IP_Data;
    wire     [C_S_AXI_DATA_WIDTH/8-1 : 0]           Bus2IP_BE;
    wire     [C_S_AXI_DATA_WIDTH-1 : 0]             IP2Bus_Data;
    wire                                            IP2Bus_RdAck;
    wire                                            IP2Bus_WrAck;
    wire                                            IP2Bus_Error;

// counters
	reg [6:0]                             AES_count;
	reg [6:0]                             AES_count_next;
	reg [6:0]                             AES_done_cnt;
	reg [6:0]                             AES_done_cnt_next;
	reg [31 : 0] total_pkt_counter;
	reg [31 : 0] total_pkt_counter_next;
	reg [31 : 0] total_pkt_counter_maxi;
	reg [31 : 0] total_pkt_counter_maxi_next;
	reg [31 : 0] total_pkt_counter_out;
	reg [31 : 0] total_pkt_counter_out_next;

	reg [NUM_STATES-1:0] tlast_end_state;									// number of state when tlast flag occured
	reg [NUM_STATES-1:0] tlast_end_state_next;
	reg [NUM_STATES-1:0] tlast_end_state_maxi;									// number of state when tlast flag occured
	reg [NUM_STATES-1:0] tlast_end_state_maxi_next;

	reg [255:0] data_out_temp;									// temp register used to store value from AES data_out, unused after synthesis

//AES modules registers
		reg [12 : 1] AES_kld;
		wire [24 : 1] AES_done;
		reg [127:0] AES_key;
		reg [127:0] AES_key_next;			// to prevent latches
		reg [255:0] AES_text_in;
		wire [127: 0] AES_text_out_1, AES_text_out_2, AES_text_out_3, AES_text_out_4, AES_text_out_5, AES_text_out_6, AES_text_out_7, AES_text_out_8, AES_text_out_9, AES_text_out_10, AES_text_out_11, AES_text_out_12, AES_text_out_13, AES_text_out_14, AES_text_out_15, AES_text_out_16, AES_text_out_17, AES_text_out_18, AES_text_out_19, AES_text_out_20, AES_text_out_21, AES_text_out_22, AES_text_out_23, AES_text_out_24;


	//registers and wires
	
	localparam NUM_RW_REGS       = 7;
	localparam NUM_RO_REGS       = 5;
    wire     [NUM_RW_REGS*C_S_AXI_DATA_WIDTH-1 : 0] rw_regs;
    wire     [NUM_RO_REGS*C_S_AXI_DATA_WIDTH-1 : 0] ro_regs;

	// RO REGS

	wire [31:0] ro_regs_signals;
	// wire [31:0] tlast_end_state_ro_regs;
	// wire [31:0] tlast_end_state_maxi_ro_regs;
	// wire [31:0] state_ro_regs;
	// wire [31:0] in_fifo_empty_ro_regs;
	// wire [31:0] in_fifo_nearly_full_ro_regs;
	// wire [31:0] out_fifo_empty_ro_regs;
	// wire [31:0] out_fifo_nearly_full_ro_regs;
	// wire [31:0] maxi_fifo_empty_ro_regs;
	// wire [31:0] maxi_fifo_nearly_full_ro_regs;
	// wire [31:0] AES_count_ro_regs;
	// wire [31:0] AES_done_cnt_ro_regs;
	
	// RW REGS
	localparam KEY_EN_REG_ADDR	= 4; // enable address for AES key
	localparam AES_EN_REG_ADDR	= 5; // address for enable signal for AES modules
	localparam AES_RESET_REG_ADDR	= 6; // address for reset for AES modules

	reg [127 : 0] key_all_reg; // AES key
    reg key_en_reg; //AES key ready - 1 ON, 0 OFF
	reg AES_en_reg; // 1 - data through AES, 0 - dataflow without AES mkodules
	reg AES_reset;

	reg [127 : 0] key_all_reg_next; // AES key nex
    reg key_en_reg_next; //AES key ready next - 1 ON, 0 OFF
	reg AES_en_reg_next;
	reg AES_reset_next;
	


//------------------------- Modules-------------------------------

    fallthrough_small_fifo #(.WIDTH(C_S_AXIS_DATA_WIDTH+C_S_AXIS_TUSER_WIDTH+(C_S_AXIS_DATA_WIDTH / 8) +1), .MAX_DEPTH_BITS(2))
    input_fifo
    (.din ({s_axis_tuser,s_axis_tdata,s_axis_tstrb,s_axis_tlast}),     // Data inclk
    .wr_en (s_axis_tvalid & ~in_fifo_nearly_full),               // Write enable
    .rd_en (in_fifo_rd_en),       // Read the next word 
    .dout ({in_fifo_ctrl_dout, in_fifo_data_dout,in_fifo_tstrb_dout,in_fifo_tlast_dout}),
    .full (),
    .nearly_full (in_fifo_nearly_full), 
    .empty (in_fifo_empty),
    .reset (~axi_resetn | AES_reset),
    .clk   (axi_aclk)
    );

   fallthrough_small_fifo #(.WIDTH(C_S_AXIS_DATA_WIDTH+C_S_AXIS_TUSER_WIDTH+(C_S_AXIS_DATA_WIDTH / 8) +1), .MAX_DEPTH_BITS(6)) // DEPTH equal = 256*2^6 [b]
   output_fifo
   (.din ({out_fifo_tuser, out_fifo_data, out_fifo_tstrb, out_fifo_tlast}),     // Data inclk
    .wr_en (out_fifo_tvalid & ~out_fifo_nearly_full),               	      // Write enable
    .rd_en (out_fifo_rd_en),       					      // Read the next word 
    .dout ({out_fifo_ctrl_dout, out_fifo_data_dout, out_fifo_tstrb_dout, out_fifo_tlast_dout}),
    .full (),
    .nearly_full (out_fifo_nearly_full), 
    .empty (out_fifo_empty),
    .reset (~axi_resetn | AES_reset),
    .clk   (axi_aclk)
   );
   
   fallthrough_small_fifo #(.WIDTH(C_S_AXIS_DATA_WIDTH+C_S_AXIS_TUSER_WIDTH+(C_S_AXIS_DATA_WIDTH / 8) +1), .MAX_DEPTH_BITS(2)) // DEPTH equal = 256*2^2 [b]
   maxi_fifo
   (.din ({maxi_fifo_tuser, maxi_fifo_data, maxi_fifo_tstrb, maxi_fifo_tlast}),     // Data inclk
    .wr_en (maxi_fifo_tvalid & ~maxi_fifo_nearly_full),               	      // Write enable
    .rd_en (maxi_fifo_rd_en),       					      // Read the next word 
    .dout ({maxi_fifo_ctrl_dout, maxi_fifo_data_dout, maxi_fifo_tstrb_dout, maxi_fifo_tlast_dout}),
    .full (),
    .nearly_full (maxi_fifo_nearly_full), 
    .empty (maxi_fifo_empty),
    .reset (~axi_resetn | AES_reset),
    .clk   (axi_aclk)
   );

	
	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_1
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[1]), 
		 .done 		(AES_done[1]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_1) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_2
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[1]), 
		 .done 		(AES_done[2]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_2) 

		);
		
	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_3
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[2]), 
		 .done 		(AES_done[3]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_3) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_4
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[2]), 
		 .done 		(AES_done[4]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_4) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_5
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[3]), 
		 .done 		(AES_done[5]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_5) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_6
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[3]), 
		 .done 		(AES_done[6]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_6) 

		);


	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_7
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[4]), 
		 .done 		(AES_done[7]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_7) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_8
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[4]), 
		 .done 		(AES_done[8]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_8) 

		);
	wrapper_aes_cipher_top		
		wrapper_aes_cipher_top_9
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[5]), 
		 .done 		(AES_done[9]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_9) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_10
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[5]), 
		 .done 		(AES_done[10]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_10) 

		);
		
	wrapper_aes_cipher_top		
		wrapper_aes_cipher_top_11
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[6]), 
		 .done 		(AES_done[11]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_11) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_12
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[6]), 
		 .done 		(AES_done[12]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_12) 

		);
		
	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_13
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[7]), 
		 .done 		(AES_done[13]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_13) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_14
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[7]), 
		 .done 		(AES_done[14]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_14) 

		);
		
	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_15
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[8]), 
		 .done 		(AES_done[15]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_15) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_16
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[8]), 
		 .done 		(AES_done[16]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_16) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_17
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[9]), 
		 .done 		(AES_done[17]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_17) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_18
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[9]), 
		 .done 		(AES_done[18]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_18) 

		);


	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_19
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[10]), 
		 .done 		(AES_done[19]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_19) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_20
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[10]), 
		 .done 		(AES_done[20]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_20) 

		);
	wrapper_aes_cipher_top		
		wrapper_aes_cipher_top_21
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[11]), 
		 .done 		(AES_done[21]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_21) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_22
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[11]), 
		 .done 		(AES_done[22]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_22) 

		);
		
	wrapper_aes_cipher_top		
		wrapper_aes_cipher_top_23
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[12]), 
		 .done 		(AES_done[23]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[127:0]),
		 .text_out	(AES_text_out_23) 

		);

	wrapper_aes_cipher_top
		wrapper_aes_cipher_top_24
		(
		 .clk		(axi_aclk),
		 .rst		(axi_resetn & (~AES_reset)),
		 .kld		(AES_kld[12]), 
		 .done 		(AES_done[24]),
		 .key		(AES_key),
		 .text_in	(AES_text_in[255:128]),
		 .text_out	(AES_text_out_24) 

		);
   


//-------------------------Logic-----------------------------------
   assign  s_axis_tready = !in_fifo_nearly_full;


// Creating a mask signal by extending the tstrb field
// There are some more efficient ways, but this will work with any tool chain
      assign  tstrb_extended[7:0] = {8{in_fifo_tstrb_dout[0]}};
      assign  tstrb_extended[15:8] = {8{in_fifo_tstrb_dout[1]}};
      assign  tstrb_extended[23:16] = {8{in_fifo_tstrb_dout[2]}};
      assign  tstrb_extended[31:24] = {8{in_fifo_tstrb_dout[3]}};
      assign  tstrb_extended[39:32] = {8{in_fifo_tstrb_dout[4]}};
      assign  tstrb_extended[47:40] = {8{in_fifo_tstrb_dout[5]}};
      assign  tstrb_extended[55:48] = {8{in_fifo_tstrb_dout[6]}};
      assign  tstrb_extended[63:56] = {8{in_fifo_tstrb_dout[7]}};
      assign  tstrb_extended[71:64] = {8{in_fifo_tstrb_dout[8]}};
      assign  tstrb_extended[79:72] = {8{in_fifo_tstrb_dout[9]}};
      assign  tstrb_extended[87:80] = {8{in_fifo_tstrb_dout[10]}};
      assign  tstrb_extended[95:88] = {8{in_fifo_tstrb_dout[11]}};
      assign  tstrb_extended[103:96] = {8{in_fifo_tstrb_dout[12]}};
      assign  tstrb_extended[111:104] = {8{in_fifo_tstrb_dout[13]}}; 
      assign  tstrb_extended[119:112] = {8{in_fifo_tstrb_dout[14]}};
      assign  tstrb_extended[127:120] = {8{in_fifo_tstrb_dout[15]}};
      assign  tstrb_extended[135:128] = {8{in_fifo_tstrb_dout[16]}};
      assign  tstrb_extended[143:136] = {8{in_fifo_tstrb_dout[17]}};
      assign  tstrb_extended[151:144] = {8{in_fifo_tstrb_dout[18]}};
      assign  tstrb_extended[159:152] = {8{in_fifo_tstrb_dout[19]}};
      assign  tstrb_extended[167:160] = {8{in_fifo_tstrb_dout[20]}};
      assign  tstrb_extended[175:168] = {8{in_fifo_tstrb_dout[21]}};
      assign  tstrb_extended[183:176] = {8{in_fifo_tstrb_dout[22]}};
      assign  tstrb_extended[191:184] = {8{in_fifo_tstrb_dout[23]}};
      assign  tstrb_extended[199:192] = {8{in_fifo_tstrb_dout[24]}};
      assign  tstrb_extended[207:200] = {8{in_fifo_tstrb_dout[25]}};
      assign  tstrb_extended[215:208] = {8{in_fifo_tstrb_dout[26]}};
      assign  tstrb_extended[223:216] = {8{in_fifo_tstrb_dout[27]}};
      assign  tstrb_extended[231:224] = {8{in_fifo_tstrb_dout[28]}};
      assign  tstrb_extended[239:232] = {8{in_fifo_tstrb_dout[29]}};
      assign  tstrb_extended[247:240] = {8{in_fifo_tstrb_dout[30]}}; 
      assign  tstrb_extended[255:248] = {8{in_fifo_tstrb_dout[31]}};

/*********************************************************************
 * Wait until the ethernet header has been decoded and the output
 * port is found, then write the module header and move the packet
 * to the output
 **********************************************************************/
always @(*) begin

	state_next = state;
	AES_count_next = AES_count;
	total_pkt_counter_next = total_pkt_counter;
	
	tlast_end_state_next = tlast_end_state;
	
	AES_kld = 0;
	////AES_kld_next = 0;
	AES_key_next = AES_key;

	out_fifo_tvalid = 0; // write flags to output fifo

	in_fifo_rd_en = 0; // read flag from output fifo
	
	AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
	AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
	AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
	AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
	AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
	AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
	AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
	AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
	AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
	AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
	AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
	AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
	AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
	AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
	AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
	AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
	AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
	AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
	AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
	AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
	AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
	AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
	AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
	AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
	AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
	AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
	AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
	AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
	AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
	AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
	AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
	AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];

	out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
	out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
	out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo
	out_fifo_data = in_fifo_data_dout; 		// do not save next data to FIFO, go to AES modules

	if (~axi_resetn || (AES_reset == 1'b1)) begin
		////AES_kld_next = 12'b0;
		total_pkt_counter_next = 0;

		AES_key_next = 128'h0; // set default key 0s
		AES_count_next = 0;

		tlast_end_state_next = 0;

		state_next = AES_INIT;                   
	end
	else begin

	case(state)

	//////////////////////////////////////////
	////////  case: AES_INIT  //////////////////////
	//////////////////////////////////////////
		AES_INIT: begin
			if (!in_fifo_empty) begin /// if fifo is NOT empty then proceed
				if (AES_en_reg) begin // AES is ON
					if (key_en_reg) begin /// waiting untill AES key registers will be actual. key_en_reg flag informs about readiness of AES key
						AES_key_next[127:96] = key_all_reg[31:0]; //// set actual key comes from PCI //////
						AES_key_next[95:64]  = key_all_reg[63:32]; // key_all_reg from PCI, changing order
						AES_key_next[63:32]  = key_all_reg[95:64];
						AES_key_next[31:0]   = key_all_reg[127:96];
					
						in_fifo_rd_en = 1;						// reading from input fifo
						
						out_fifo_data = in_fifo_data_dout; 		// first 256 bits are not touched (ETH HDR)
						out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
						out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
						out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

						out_fifo_tvalid = 1; 					// rewrite tuser and so on to output fifo						

						total_pkt_counter_next = total_pkt_counter + 1; // increment counter number
						state_next = ETH_IP_HDR;
					end
				end
				else begin               ////  AES OFF... ////
					total_pkt_counter_next = total_pkt_counter + 1; // increment counter number				
					state_next = BYPASS;  // go to BYPASS state (transparent mode from in to out)
				end
			end 
		end // AES_INIT

	//////////////////////////////////////////
	////////  ETH_IP_HDR  ////////////////////
	//////////////////////////////////////////			
		ETH_IP_HDR: begin
		// we dont encrypt second of 256 bits data portion because first 16 bit is last 16 bit of IP HDR
			if (!in_fifo_empty) begin

					in_fifo_rd_en = 1;						// read from fifo

					out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
					out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
					out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo
					out_fifo_data = in_fifo_data_dout; 		// second 256 bits are not touched (part of IP HDR is there)
					
					out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
					
				if (!in_fifo_tlast_dout) begin
				
					////AES_kld_next = 12'b000000000001 << tlast_end_state;
				
					AES_count_next = AES_count + 1;
					state_next = tlast_end_state + 1;	// go to S_AES_1 state (after reset) or to the next free state (not processing data )
													// if TLAST occurs in the last state (S_AES_12), then tlast_end_state flag is set to zero - need to go to 0 + 1 state (S_AES_1) then
				end
				else begin
					AES_count_next = 0;
					state_next = AES_INIT;
				end
			end
		end // ETH_IP_HDR

	//////////////////////////////////////////
	////////  S_AES_1  ///////////////////////
	//////////////////////////////////////////			
		S_AES_1: begin
			if (!in_fifo_empty) begin						// check if empty fifo state not occur
			
				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];
				
				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000000000001;
				
				if (!in_fifo_tlast_dout) begin					// if end of packet did not occur in previous state
				
					tlast_end_state_next = 0;			// tlast end state is not written		
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_1


	//////////////////////////////////////////
	////////  S_AES_2  ///////////////////////
	//////////////////////////////////////////	
		S_AES_2: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];	

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo				
				AES_kld = 12'b000000000010;	//set next kld to the next AES module
				
				if (!in_fifo_tlast_dout) begin
	
					tlast_end_state_next = 0;			// tlast end state is not written
			
					AES_count_next = AES_count + 1;
					state_next = state + 1;
					
				end
				else begin
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_2

		
	//////////////////////////////////////////
	////////  S_AES_3  ///////////////////////
	//////////////////////////////////////////	
		S_AES_3: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];
				
				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000000000100;	// set next kld to the next AES module
					
				if (!in_fifo_tlast_dout) begin	
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_3

		
	//////////////////////////////////////////
	////////  S_AES_4  ///////////////////////
	//////////////////////////////////////////	
		S_AES_4: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];
				
				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000000001000;	// set next kld to the next AES module
					
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_4

		
	//////////////////////////////////////////
	////////  S_AES_5  ///////////////////////
	//////////////////////////////////////////	
		S_AES_5: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];
				
				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000000010000;	//set next kld to the next AES module			
			
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written

					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_5

		
	//////////////////////////////////////////
	////////  S_AES_6  ///////////////////////
	//////////////////////////////////////////	
		S_AES_6: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];			

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000000100000;				// set next kld to the next AES module
					
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_6

		
	//////////////////////////////////////////
	////////  S_AES_7  ///////////////////////
	//////////////////////////////////////////	
		S_AES_7: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];			

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000001000000;	// set next kld to the next AES module
					
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_7

		
	//////////////////////////////////////////
	////////  S_AES_8  ///////////////////////
	//////////////////////////////////////////	
		S_AES_8: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo				
				AES_kld = 12'b000010000000;	// set next kld to the next AES module
					
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_8

		
	//////////////////////////////////////////
	////////  S_AES_9  ///////////////////////
	//////////////////////////////////////////	
		S_AES_9: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b000100000000;	//set next kld to the next AES module			
			
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_9

		
	//////////////////////////////////////////
	////////  S_AES_10  ///////////////////////
	//////////////////////////////////////////	
		S_AES_10: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];
				
				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b001000000000;	// set next kld to the next AES module
				
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_10

		
	//////////////////////////////////////////
	////////  S_AES_11  ///////////////////////
	//////////////////////////////////////////	
		S_AES_11: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];			

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b010000000000;	// set next kld to the next AES module
				
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = state + 1;
				end
				else begin						
					
					tlast_end_state_next = state;		// end in this state
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_11

		
	//////////////////////////////////////////
	////////  S_AES_12  ///////////////////////
	//////////////////////////////////////////	
		S_AES_12: begin
			if (!in_fifo_empty) begin						// first cycle of the FSM loop

				in_fifo_rd_en = 1;						// read from fifo
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo

				AES_text_in[255 : 248] = in_fifo_data_dout[7 : 0] & tstrb_extended[7 : 0];
				AES_text_in[247 : 240] = in_fifo_data_dout[15 : 8] & tstrb_extended[15 : 8];
				AES_text_in[239 : 232] = in_fifo_data_dout[23 : 16] & tstrb_extended[23 : 16];
				AES_text_in[231 : 224] = in_fifo_data_dout[31 : 24] & tstrb_extended[31 : 24];
				AES_text_in[223 : 216] = in_fifo_data_dout[39 : 32] & tstrb_extended[39 : 32];
				AES_text_in[215 : 208] = in_fifo_data_dout[47 : 40] & tstrb_extended[47 : 40];
				AES_text_in[207 : 200] = in_fifo_data_dout[55 : 48] & tstrb_extended[55 : 48];
				AES_text_in[199 : 192] = in_fifo_data_dout[63 : 56] & tstrb_extended[63 : 56];
				AES_text_in[191 : 184] = in_fifo_data_dout[71 : 64] & tstrb_extended[71 : 64];
				AES_text_in[183 : 176] = in_fifo_data_dout[79 : 72] & tstrb_extended[79 : 72];
				AES_text_in[175 : 168] = in_fifo_data_dout[87 : 80] & tstrb_extended[87 : 80];
				AES_text_in[167 : 160] = in_fifo_data_dout[95 : 88] & tstrb_extended[95 : 88];
				AES_text_in[159 : 152] = in_fifo_data_dout[103 : 96] & tstrb_extended[103 : 96];
				AES_text_in[151 : 144] = in_fifo_data_dout[111 : 104] & tstrb_extended[111 : 104];
				AES_text_in[143 : 136] = in_fifo_data_dout[119 : 112] & tstrb_extended[119 : 112];
				AES_text_in[135 : 128] = in_fifo_data_dout[127 : 120] & tstrb_extended[127 : 120];
				AES_text_in[127 : 120] = in_fifo_data_dout[135 : 128] & tstrb_extended[135 : 128];
				AES_text_in[119 : 112] = in_fifo_data_dout[143 : 136] & tstrb_extended[143 : 136];
				AES_text_in[111 : 104] = in_fifo_data_dout[151 : 144] & tstrb_extended[151 : 144];
				AES_text_in[103 : 96] = in_fifo_data_dout[159 : 152] & tstrb_extended[159 : 152];
				AES_text_in[95 : 88] = in_fifo_data_dout[167 : 160] & tstrb_extended[167 : 160];
				AES_text_in[87 : 80] = in_fifo_data_dout[175 : 168] & tstrb_extended[175 : 168];
				AES_text_in[79 : 72] = in_fifo_data_dout[183 : 176] & tstrb_extended[183 : 176];
				AES_text_in[71 : 64] = in_fifo_data_dout[191 : 184] & tstrb_extended[191 : 184];
				AES_text_in[63 : 56] = in_fifo_data_dout[199 : 192] & tstrb_extended[199 : 192];
				AES_text_in[55 : 48] = in_fifo_data_dout[207 : 200] & tstrb_extended[207 : 200];
				AES_text_in[47 : 40] = in_fifo_data_dout[215 : 208] & tstrb_extended[215 : 208];
				AES_text_in[39 : 32] = in_fifo_data_dout[223 : 216] & tstrb_extended[223 : 216];
				AES_text_in[31 : 24] = in_fifo_data_dout[231 : 224] & tstrb_extended[231 : 224];
				AES_text_in[23 : 16] = in_fifo_data_dout[239 : 232] & tstrb_extended[239 : 232];
				AES_text_in[15 : 8] = in_fifo_data_dout[247 : 240] & tstrb_extended[247 : 240];
				AES_text_in[7 : 0] = in_fifo_data_dout[255 : 248] & tstrb_extended[255 : 248];

				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				AES_kld = 12'b100000000000;	//set next kld to the next AES module			
			
				if (!in_fifo_tlast_dout) begin
					
					tlast_end_state_next = 0;			// tlast end state is not written
					
					AES_count_next = AES_count + 1;
					state_next = S_AES_1;
				end
				else begin						
					
					tlast_end_state_next = 0;		// end in this state, zapisujemy zero z uwagi na to, ze nastepnym 'wolnym' stanem jest stan 0 + 1 (S_AES_1)
					////AES_kld_next = 12'b000000000000;	// so there is no need to set kld signal for next AES modules
					
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end
			
		end //S_AES_12


		BYPASS: begin
		/// input to output  ///
			if (!in_fifo_empty) begin
			
				out_fifo_tvalid = 1;					// rewrite tuser and so on to output fifo
				in_fifo_rd_en = 1;						// read from fifo
				
				out_fifo_tstrb = in_fifo_tstrb_dout;	// save bit mask to output fifo
				out_fifo_tlast = in_fifo_tlast_dout;	// save TLAST flag to output fifo
				out_fifo_tuser = in_fifo_ctrl_dout;		// TUSER to output fifo
				out_fifo_data = in_fifo_data_dout; 		// do not save next data to FIFO, go to AES modules
				
		 
				if (in_fifo_tlast_dout) begin // is there is the last part of frame, go to AES_INIT state
					// go to AES_INIT state if tlast flag equal 1
					AES_count_next = 0;
					state_next = AES_INIT;
				end

			end 
		end //BYPASS

	endcase
	end // axi_resetn = 1
end // always @*
   
	always @(posedge axi_aclk) begin
	    state <= state_next;
		state_maxi <= state_maxi_next;
		state_out <= state_out_next;
		AES_done_cnt <= AES_done_cnt_next;
		//AES_kld <= AES_kld_next;
		AES_key <= AES_key_next;
	    AES_count <= AES_count_next;
		tlast_end_state <= tlast_end_state_next;
		tlast_end_state_maxi <= tlast_end_state_maxi_next;

		//// RO regs ////
		total_pkt_counter <= total_pkt_counter_next;
		total_pkt_counter_maxi <= total_pkt_counter_maxi_next;
		total_pkt_counter_out <= total_pkt_counter_out_next;	
	end
	
	
always @(*) begin

	state_maxi_next = state_maxi;
	AES_done_cnt_next = AES_done_cnt;
	
	tlast_end_state_maxi_next = tlast_end_state_maxi;
	
	total_pkt_counter_maxi_next = total_pkt_counter_maxi;

    out_fifo_rd_en = 0;  // read flag from output fifo

	maxi_fifo_tvalid = 0; 	// write flag to maxi fifo
	
	maxi_fifo_data = out_fifo_data_dout;  										// rewriting DATA from out to maxi fifo
	maxi_fifo_tstrb = out_fifo_tstrb_dout;	
	maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
	maxi_fifo_tlast = out_fifo_tlast_dout;

	if (~axi_resetn || (AES_reset == 1'b1)) begin

		AES_done_cnt_next = 0;
		
		total_pkt_counter_maxi_next = 0;
		
		tlast_end_state_maxi_next = 0;
		
		state_maxi_next = AES_INIT;                   
	end
	else begin

	case(state_maxi)

	//////////////////////////////////////////
	////////  case: AES_INIT  //////////////////////
	//////////////////////////////////////////
		AES_INIT: begin
			if (!out_fifo_empty) begin // if fifo is NOT empty then proceed
				if (AES_en_reg) begin 	// AES is ON
					if (key_en_reg) begin 	// waiting until key register for key_all_reg will be actual, key_en_reg informs about readiness of aes module key
					
						maxi_fifo_tvalid = 1;                 /// write to maxi fifo
						out_fifo_rd_en = 1;					  /// read from maxi fifo
						
						maxi_fifo_tuser = out_fifo_ctrl_dout;  /// TUSER from output fifo to maxi fifo
						maxi_fifo_data = out_fifo_data_dout;  /// DATA from output fifo to maxi fifo
						maxi_fifo_tstrb = out_fifo_tstrb_dout; /// TSTRB from output fifo to maxi fifo
						maxi_fifo_tlast = out_fifo_tlast_dout; /// TLAST from output fifo to maxi fifo
						
						total_pkt_counter_maxi_next = total_pkt_counter_maxi + 1; // increment counter number
						
						state_maxi_next = ETH_IP_HDR;
						
					end
				end
				else begin               ////  AES OFF... ////
				
					total_pkt_counter_maxi_next = total_pkt_counter_maxi + 1; // increment counter number
					
					state_maxi_next = BYPASS;  // go to BYPASS state (transparent mode from in to out)
				end
			end 
		end // AES_INIT	
	
	//////////////////////////////////////////
	////////  case: ETH_IP_HDR  //////////////
	//////////////////////////////////////////
		ETH_IP_HDR: begin

			if (!out_fifo_empty) begin
			
				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				maxi_fifo_tuser = out_fifo_ctrl_dout;  /// TUSER from output fifo to maxi fifo
				maxi_fifo_data = out_fifo_data_dout;  /// DATA from output fifo to maxi fifo
				maxi_fifo_tstrb = out_fifo_tstrb_dout; /// TSTRB from output fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout; /// TLAST from output fifo to maxi fifo
				
				
				if (!out_fifo_tlast_dout) begin

					AES_done_cnt_next = 1;
					state_maxi_next = tlast_end_state_maxi + 1;		// go to S_AES_1 state (after the reset) or to this which will first send crypted data

			   end
			   else begin
			   
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;		// go to AES_INIT state
					
			   end
			end
		end //ETH_IP_HDR


	//////////////////////////////////////////
	////////  S_AES_1  ///////////////////////
	//////////////////////////////////////////		
		S_AES_1: begin
			if ((AES_done[1] && AES_done[2])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_2, AES_text_out_1}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_1


	//////////////////////////////////////////
	////////  S_AES_2  ///////////////////////
	//////////////////////////////////////////		
		S_AES_2: begin
			if ((AES_done[3] && AES_done[4])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_4, AES_text_out_3}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_2

		
	//////////////////////////////////////////
	////////  S_AES_3  ///////////////////////
	//////////////////////////////////////////		
		S_AES_3: begin
			if ((AES_done[5] && AES_done[6])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_6, AES_text_out_5}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_3

		
	//////////////////////////////////////////
	////////  S_AES_4  ///////////////////////
	//////////////////////////////////////////		
		S_AES_4: begin
			if ((AES_done[7] && AES_done[8])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_8, AES_text_out_7}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_4

		
	//////////////////////////////////////////
	////////  S_AES_5  ///////////////////////
	//////////////////////////////////////////		
		S_AES_5: begin
			if ((AES_done[9] && AES_done[10])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_10, AES_text_out_9}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_5

		
	//////////////////////////////////////////
	////////  S_AES_6  ///////////////////////
	//////////////////////////////////////////		
		S_AES_6: begin
			if ((AES_done[11] && AES_done[12])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_12, AES_text_out_11}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_6

		
	//////////////////////////////////////////
	////////  S_AES_7  ///////////////////////
	//////////////////////////////////////////		
		S_AES_7: begin
			if ((AES_done[13] && AES_done[14])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_14, AES_text_out_13}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_7

		
	//////////////////////////////////////////
	////////  S_AES_8  ///////////////////////
	//////////////////////////////////////////		
		S_AES_8: begin
			if ((AES_done[15] && AES_done[16])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_16, AES_text_out_15}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_8

		
	//////////////////////////////////////////
	////////  S_AES_9  ///////////////////////
	//////////////////////////////////////////		
		S_AES_9: begin
			if ((AES_done[17] && AES_done[18])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_18, AES_text_out_17}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_9

		
	//////////////////////////////////////////
	////////  S_AES_10  ///////////////////////
	//////////////////////////////////////////		
		S_AES_10: begin
			if ((AES_done[19] && AES_done[20])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_20, AES_text_out_19}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_10

		
	//////////////////////////////////////////
	////////  S_AES_11  ///////////////////////
	//////////////////////////////////////////		
		S_AES_11: begin
			if ((AES_done[21] && AES_done[22])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_22, AES_text_out_21}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = state_maxi;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = state_maxi + 1;
				end
				
			end
	
		end //S_AES_11

		
	//////////////////////////////////////////
	////////  S_AES_12  ///////////////////////
	//////////////////////////////////////////		
		S_AES_12: begin
			if ((AES_done[23] && AES_done[24])) begin 					// AES cipher is ready

				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				
				maxi_fifo_tuser = out_fifo_ctrl_dout;  										// rewriting TUSER from out fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout;
				
				data_out_temp = {AES_text_out_24, AES_text_out_23}; 	// auxiliary variable, will be cut after synthesis (present AES cipher)						
				maxi_fifo_data[255 : 248] = data_out_temp[7 : 0]; 
				maxi_fifo_data[247 : 240] = data_out_temp[15 : 8];
				maxi_fifo_data[239 : 232] = data_out_temp[23 : 16];
				maxi_fifo_data[231 : 224] = data_out_temp[31 : 24];
				maxi_fifo_data[223 : 216] = data_out_temp[39 : 32];
				maxi_fifo_data[215 : 208] = data_out_temp[47 : 40];
				maxi_fifo_data[207 : 200] = data_out_temp[56 : 48];
				maxi_fifo_data[199 : 192] = data_out_temp[63 : 56];
				maxi_fifo_data[191 : 184] = data_out_temp[71 : 64];
				maxi_fifo_data[183 : 176] = data_out_temp[79 : 72];
				maxi_fifo_data[175 : 168] = data_out_temp[87 : 80];
				maxi_fifo_data[167 : 160] = data_out_temp[95 : 88];
				maxi_fifo_data[159 : 152] = data_out_temp[103 : 96];
				maxi_fifo_data[151 : 144] = data_out_temp[111 : 104];
				maxi_fifo_data[143 : 136] = data_out_temp[119 : 112];
				maxi_fifo_data[135 : 128] = data_out_temp[127 : 120];
				maxi_fifo_data[127 : 120] = data_out_temp[135 : 128];
				maxi_fifo_data[119 : 112] = data_out_temp[143 : 136];
				maxi_fifo_data[111 : 104] = data_out_temp[151 : 144];
				maxi_fifo_data[103 : 96] = data_out_temp[159 : 152];
				maxi_fifo_data[95 : 88] = data_out_temp[167 : 160];
				maxi_fifo_data[87 : 80] = data_out_temp[175 : 168];
				maxi_fifo_data[79 : 72] = data_out_temp[183 : 176];
				maxi_fifo_data[71 : 64] = data_out_temp[191 : 184];
				maxi_fifo_data[63 : 56] = data_out_temp[199 : 192];
				maxi_fifo_data[55 : 48] = data_out_temp[207 : 200];
				maxi_fifo_data[47 : 40] = data_out_temp[215 : 208];
				maxi_fifo_data[39 : 32] = data_out_temp[223 : 216];
				maxi_fifo_data[31 : 24] = data_out_temp[231 : 224];
				maxi_fifo_data[23 : 16] = data_out_temp[239 : 232];
				maxi_fifo_data[15 : 8] = data_out_temp[247 : 240];
				maxi_fifo_data[7 : 0] = data_out_temp[255 : 248];	
				
				if (out_fifo_tlast_dout) begin 					// is the last part of frame, go to ETH_IP_HDR state
				
					if (out_fifo_tstrb_dout <= 32'h0000FFFF) begin
						maxi_fifo_tstrb = 32'h0000FFFF;			// bit validity (TSTRB) may be 128 or 256 bits (AES output cipher is always 128 bits, 2 AES)
					end
					else begin
						maxi_fifo_tstrb = 32'hFFFFFFFF;
					end
					
					tlast_end_state_maxi_next = 0;		// end in this state, write 0 because the next free state will be S_AES_1 state (0+1)
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
					
				end
				else begin

					maxi_fifo_tstrb = out_fifo_tstrb_dout;		// rewrite tsrtb flag
				
					AES_done_cnt_next = AES_done_cnt + 1;
					state_maxi_next = S_AES_1;
				end
				
			end
	
		end //S_AES_12

		
	//////////////////////////////////////////
	////////  case: BYPASS  //////////////////
	//////////////////////////////////////////
		BYPASS: begin
		/// input to output  ///
			if (!out_fifo_empty) begin
			
				maxi_fifo_tvalid = 1;                 /// write to maxi fifo
				out_fifo_rd_en = 1;					  /// read from maxi fifo
				maxi_fifo_tuser = out_fifo_ctrl_dout;  /// TUSER from output fifo to maxi fifo
				maxi_fifo_data = out_fifo_data_dout;  /// DATA from output fifo to maxi fifo
				maxi_fifo_tstrb = out_fifo_tstrb_dout; /// TSTRB from output fifo to maxi fifo
				maxi_fifo_tlast = out_fifo_tlast_dout; /// TLAST from output fifo to maxi fifo
					
				if (out_fifo_tlast_dout) begin // is there is the last part of frame, go to AES_INIT state
					AES_done_cnt_next = 0;
					state_maxi_next = AES_INIT;
				end

			end 
		end // BYPASS

	endcase
	end // axi_resetn = 1
end // always @*



//zapis do magistrali maxi

always @(*) begin

	state_out_next = state_out;

	total_pkt_counter_out_next = total_pkt_counter_out;
	
	maxi_fifo_rd_en = 0;  // read flag from output fifo

	m_axis_tvalid = 0; 	// write flag to maxi fifo
	
	m_axis_tuser = maxi_fifo_ctrl_dout;
	m_axis_tdata = maxi_fifo_data_dout;
	m_axis_tstrb = maxi_fifo_tstrb_dout;
	m_axis_tlast = maxi_fifo_tlast_dout;

	if (~axi_resetn || (AES_reset == 1'b1)) begin
		
		total_pkt_counter_out_next = 0;
		
		state_out_next = 0;
		
	end
	else begin

		case(state_out)	


			0 : begin //if new frame arrived - wait for bus, set tvalid and go to next state

				if (!maxi_fifo_empty) begin

					m_axis_tvalid = 1;                  /// ready flag for maxi output data

					m_axis_tuser = maxi_fifo_ctrl_dout;  /// TUSER from output fifo to m_axis bus
					m_axis_tdata = maxi_fifo_data_dout;  /// DATA from output fifo to m_axis bus
					m_axis_tstrb = maxi_fifo_tstrb_dout; /// TSTRB from output fifo to m_axis bus
					m_axis_tlast = maxi_fifo_tlast_dout; /// TLAST from output fifo to m_axis bus
					
					total_pkt_counter_out_next = total_pkt_counter_out + 1;
					
					state_out_next = 1;
					
				end
			end

			1 : begin // transmituj ramke, az do jej konca

					if (!maxi_fifo_empty && m_axis_tready) begin
						m_axis_tvalid = 1;                  /// ready flag for maxi output data
						maxi_fifo_rd_en = 1;
						m_axis_tuser = maxi_fifo_ctrl_dout;  /// TUSER from output fifo to m_axis bus
						m_axis_tdata = maxi_fifo_data_dout;  /// DATA from output fifo to m_axis bus
						m_axis_tstrb = maxi_fifo_tstrb_dout; /// TSTRB from output fifo to m_axis bus
						m_axis_tlast = maxi_fifo_tlast_dout; /// TLAST from output fifo to m_axis bus
						
						if (maxi_fifo_tlast_dout) begin //go to the wait-for-next-frame state
							state_out_next = 0;
						end
						
					end
			end
		endcase
	
	end
end //always



//Registers section
// -- AXILITE IPIF
  axi_lite_ipif_1bar 
  #(
    .C_S_AXI_DATA_WIDTH (C_S_AXI_DATA_WIDTH),
    .C_S_AXI_ADDR_WIDTH (C_S_AXI_ADDR_WIDTH),
    .C_USE_WSTRB        (C_USE_WSTRB),
    .C_DPHASE_TIMEOUT   (C_DPHASE_TIMEOUT),
    .C_BAR0_BASEADDR    (C_BASEADDR),
    .C_BAR0_HIGHADDR    (C_HIGHADDR)
  ) axi_lite_ipif_inst
  (
    .S_AXI_ACLK          ( S_AXI_ACLK     ),
    .S_AXI_ARESETN       ( S_AXI_ARESETN  ),
    .S_AXI_AWADDR        ( S_AXI_AWADDR   ),
    .S_AXI_AWVALID       ( S_AXI_AWVALID  ),
    .S_AXI_WDATA         ( S_AXI_WDATA    ),
    .S_AXI_WSTRB         ( S_AXI_WSTRB    ),
    .S_AXI_WVALID        ( S_AXI_WVALID   ),
    .S_AXI_BREADY        ( S_AXI_BREADY   ),
    .S_AXI_ARADDR        ( S_AXI_ARADDR   ),
    .S_AXI_ARVALID       ( S_AXI_ARVALID  ),
    .S_AXI_RREADY        ( S_AXI_RREADY   ),
    .S_AXI_ARREADY       ( S_AXI_ARREADY  ),
    .S_AXI_RDATA         ( S_AXI_RDATA    ),
    .S_AXI_RRESP         ( S_AXI_RRESP    ),
    .S_AXI_RVALID        ( S_AXI_RVALID   ),
    .S_AXI_WREADY        ( S_AXI_WREADY   ),
    .S_AXI_BRESP         ( S_AXI_BRESP    ),
    .S_AXI_BVALID        ( S_AXI_BVALID   ),
    .S_AXI_AWREADY       ( S_AXI_AWREADY  ),
	
	// Controls to the IP/IPIF modules
    .Bus2IP_Clk          ( Bus2IP_Clk     ),
    .Bus2IP_Resetn       ( Bus2IP_Resetn  ),
    .Bus2IP_Addr         ( Bus2IP_Addr    ),
    .Bus2IP_RNW          ( Bus2IP_RNW     ),
    .Bus2IP_BE           ( Bus2IP_BE      ),
    .Bus2IP_CS           ( Bus2IP_CS      ),
    .Bus2IP_Data         ( Bus2IP_Data    ),
    .IP2Bus_Data         ( IP2Bus_Data    ),
    .IP2Bus_WrAck        ( IP2Bus_WrAck   ),
    .IP2Bus_RdAck        ( IP2Bus_RdAck   ),
    .IP2Bus_Error        ( IP2Bus_Error   )
  );

  // -- IPIF REGS
  ipif_regs 
  #(
    .C_S_AXI_DATA_WIDTH (C_S_AXI_DATA_WIDTH),          
    .C_S_AXI_ADDR_WIDTH (C_S_AXI_ADDR_WIDTH),   
    .NUM_RW_REGS        (NUM_RW_REGS),
    .NUM_RO_REGS        (NUM_RO_REGS)
  ) ipif_regs_inst
  (   
    .Bus2IP_Clk     ( Bus2IP_Clk     ),
    .Bus2IP_Resetn  ( Bus2IP_Resetn  ), 
    .Bus2IP_Addr    ( Bus2IP_Addr    ),
    .Bus2IP_CS      ( Bus2IP_CS[0]   ),
    .Bus2IP_RNW     ( Bus2IP_RNW     ),
    .Bus2IP_Data    ( Bus2IP_Data    ),
    .Bus2IP_BE      ( Bus2IP_BE      ),
    .IP2Bus_Data    ( IP2Bus_Data    ),
    .IP2Bus_RdAck   ( IP2Bus_RdAck   ),
    .IP2Bus_WrAck   ( IP2Bus_WrAck   ),
    .IP2Bus_Error   ( IP2Bus_Error   ),
	
    .rw_regs        ( rw_regs ),
    .ro_regs        ( ro_regs )
  );

  
// assign tlast_end_state_ro_regs = { 27'b000000000000000000000000000, tlast_end_state };
// assign tlast_end_state_maxi_ro_regs = { 27'b000000000000000000000000000, tlast_end_state_maxi };
// assign state_ro_regs = { 27'b000000000000000000000000000, state };
// assign in_fifo_empty_ro_regs = { 31'b0000000000000000000000000000000, in_fifo_empty };
// assign in_fifo_nearly_full_ro_regs = { 31'b0000000000000000000000000000000, in_fifo_nearly_full };
// assign out_fifo_empty_ro_regs = { 31'b0000000000000000000000000000000, out_fifo_empty };
// assign out_fifo_nearly_full_ro_regs = { 31'b0000000000000000000000000000000, out_fifo_nearly_full };
// assign maxi_fifo_empty_ro_regs = { 31'b0000000000000000000000000000000, maxi_fifo_empty };
// assign maxi_fifo_nearly_full_ro_regs = { 31'b0000000000000000000000000000000, maxi_fifo_nearly_full };
// assign AES_count_ro_regs = { 23'b00000000000000000000000, AES_count };
// assign AES_done_cnt_ro_regs = { 23'b00000000000000000000000, AES_done_cnt };

assign ro_regs_signals = {	AES_count, 				// 7b
							AES_done_cnt, 			// 7b
							in_fifo_empty, 			// 1b
							in_fifo_nearly_full, 	// 1b
							out_fifo_empty, 		// 1b
							out_fifo_nearly_full,	// 1b
							maxi_fifo_empty,		// 1b		
							maxi_fifo_nearly_full,	// 1b			
							tlast_end_state_maxi, 	// 4b
							tlast_end_state, 		// 4b
							state					// 4b
						};

assign ro_regs = {	total_pkt_counter, 
					total_pkt_counter_maxi,
					total_pkt_counter_out,
					
					ro_regs_signals
 };

/*address: 	0x001C (ro_regs_signals)
			0x0020 (total_pkt_counter_out)
			0x0024 (total_pkt_counter_maxi)
			0x0028 (total_pkt_counter)
			
*/

 
/*address: 	0x001C (maxi_fifo_nearly_full_ro_regs)
			0x0020 (maxi_fifo_empty_ro_regs)
			0x0024 (tlast_end_state_ro_regs)
			0x0028 (state_ro_regs)
			0x002C (in_fifo_empty_ro_regs)
			0x0030 (in_fifo_nearly_full_ro_regs)
			0x0034 (out_fifo_empty_ro_regs)
			0x0038 (out_fifo_nearly_full_ro_regs)
			0x003C (AES_count_ro_regs)
			0x0040 (AES_done_cnt_ro_regs)
			0x0044 (total_pkt_counter)
			0x0048 (total_pkt_counter_maxi)
			0x004C (tlast_end_state_maxi_ro_regs)
			0x0050 (total_pkt_counter_out)
			
*/
always @(posedge Bus2IP_Clk)
	if (~Bus2IP_Resetn || (AES_reset == 1'b1)) begin
	/// RW regs ///
		key_en_reg_next   <= 'b0;
		key_all_reg_next  <= 128'h00000000000000000000000000000000;
		AES_en_reg_next  <= 'b0;
		AES_reset_next <= 'b0;
		
		key_en_reg   <= 'b0;
		key_all_reg  <= 128'h00000000000000000000000000000000;
		AES_en_reg  <= 'b0;
		AES_reset <= 'b0;	
	end
	else begin
	/// RW regs ///
		key_all_reg_next <= rw_regs[127 : 0];
		key_en_reg_next <= rw_regs [C_S_AXI_DATA_WIDTH * (KEY_EN_REG_ADDR)];
		AES_en_reg_next <= rw_regs [C_S_AXI_DATA_WIDTH * (AES_EN_REG_ADDR)];
		AES_reset_next <= rw_regs [C_S_AXI_DATA_WIDTH * (AES_RESET_REG_ADDR)];
		
		key_all_reg <= key_all_reg_next;
		key_en_reg <= key_en_reg_next;
		AES_en_reg <= AES_en_reg_next;
		AES_reset <= AES_reset_next;
	end


endmodule // nf10_aes