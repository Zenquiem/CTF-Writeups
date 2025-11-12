from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./calc')
#p = remote('geek.ctfplus.cn',30971)
# 1. 通过 Banner
# 发送一个换行符来通过 getchar()
p.recvuntil(b"Press any key to start...")
p.sendline(b"")
# 2. 循环解决 50 个问题
for i in range(50):
        # 接收第一个数字（把前面的省略）
        p.recvuntil(b": ")
        # drop=True 会丢弃 " * " 分隔符
        num1_bytes = p.recvuntil(b" * ", drop=True)
        # 接收到 " = " 之前的所有字节，这就是第二个数字
        # drop=True作用一样
        num2_bytes = p.recvuntil(b" = ", drop=True)
        # 将字节转换成整数用于计算 (但是我们接收并没有排除空格，lstrip() 用于去除存在的空格)
        num1 = int(num1_bytes.lstrip())
        num2 = int(num2_bytes.lstrip())
        # 计算
        result = num1 * num2
        # 发送答案。（sendline：在发送完内容后会自动加一个\n，这告诉scanf输入完毕，继续运行，而send不会添加\n，如果用send会卡在scanf）
        p.sendline(str(result).encode())
# 3. 获取 Shell
p.interactive()
