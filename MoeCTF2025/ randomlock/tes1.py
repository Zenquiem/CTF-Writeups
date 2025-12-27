from pwn import *
import sys
context(arch='amd64', os='linux')

file_name = './pwn'

elf = ELF(file_name)

gdb_   = 1 if ('gdb' in sys.argv)        else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1

if switch:
    target = '127.0.0.1'
    port   = 41631
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
r    = lambda numb=4096           : p.recv(numb)
ru   = lambda delim, drop=True    : p.recvuntil(delim, drop)
rl   = lambda                     : p.recvline()
lg   = lambda name, data          : log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
ra   = lambda t=None              : p.recvall(timeout=t)
cl   = lambda                     : p.close()
it   = lambda                     : p.interactive()
uu64 = lambda data                : u64(data.ljust(8, b'\x00'))

#################################################################################
from ctypes import *
while True:
    try:
        if switch:
            target = '127.0.0.1'
            port   = 41631
            p = remote(target, port)
        else:
            p = process(file_name)
        lib = cdll.LoadLibrary('./tes3.so')
        lib.get_seed()
        for i in range(10):
            v6 = lib.get_v6()
            sla(b'>',str(v6).encode())   
        result = ra(1)
        if b'{' in result or b'flag' in result or b'win' in result:
            lg("flag",result)
            it()
            break
        else:
            cl()
    except EOFError:
        cl()
        continue        
    except Exception as e:
        cl()
        continue 