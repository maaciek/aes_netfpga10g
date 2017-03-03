#
# AXI4-Lite stimuli
#

#writing to the crypto module
#####################################################################
######### UWAGA!!! ZAKRES ADRESOW MODULU AES: 0x7A400000 - 0x7A40ffff
#####################################################################

########################################
######### REGISTERS MAP ################
########################################
####### RW REGISTERS
# offset 0x0 -   encryption key part1
# offset 0x4 -   encryption key part2
# offset 0x8 -   encryption key part3
# offset 0xC -   encryption key part4
# offset 0x10 -  AES key enable (1bit)
# offset 0x14 -  AES enable (1bit)
# offset 0x18 -  AES reset (1bit)

####### RO REGISTERS
# offset 0x1C -  ro_regs_signals
# offset 0x20 -  total_pkt_counter_out
# offset 0x24 -  total_pkt_counter_maxi
# offset 0x28 -  total_pkt_counter

#################################################################


7A400014, 00000001, f, -. ###### wlaczenie modulu AES w sciezke danych


### klucz: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF(HEX) ###
7A400010, 00000000, f, -. # ustawienie flagi - klucz AES nieaktualny
7A400000, FFFFFFFF, f, -. # wpisanie 1-ej czesci klucza AES (32b)
7A400004, FFFFFFFF, f, -. # wpisanie 2-ej czesci klucza AES (32b)
7A400008, FFFFFFFF, f, -. # wpisanie 3-ej czesci klucza AES (32b)
7A40000C, FFFFFFFF, f, -. # wpisanie 4-ej czesci klucza AES (32b)

7A400010, 00000001, f, -. # ustawienie flagi - klucz AES aktualny

### OPOZNIENIE ODCZYTU O 6 us ###
@6000
### klucz: 10203040 50607080 90A0B0C0 D0E0F034(HEX)
7A400000, 10203040, f, -. # wpisanie 1-ej czesci klucza AES (32b)
7A400004, 50607080, f, -. # wpisanie 2-ej czesci klucza AES (32b)
7A400008, 90A0B0C0, f, -. # wpisanie 3-ej czesci klucza AES (32b)
7A40000C, D0E0F034, f, -. # wpisanie 4-ej czesci klucza AES (32b)
#################################################################

############################ ODCZYT RO REGS #####################
@15800		   ### opoznienie odczytu
- , -, -, 7A40001C. # ro_regs_signals
- , -, -, 7A400020. # total_pkt_counter_out
- , -, -, 7A400024. # total_pkt_counter_maxi
- , -, -, 7A400028. # total_pkt_counter