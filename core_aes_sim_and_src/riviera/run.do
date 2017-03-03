alib work work

vlog -dbg ../src/aes_sbox.v
vlog -dbg ../src/aes_rcon.v
vlog -dbg ../src/aes_key_expand_128.v
vlog -dbg ../src/aes_cipher_top.v
vlog -dbg ../src/wrapper_aes_cipher_top.v
vlog -dbg ../src/test_bench_top.v

asim +r +w +access test

system.open -wave
wave sim:/test/top/clk
wave sim:/test/top/rst
wave sim:/test/top/ld
wave sim:/test/top/done
wave sim:/test/top/key
wave sim:/test/top/text_in
wave sim:/test/top/text_out

run -all