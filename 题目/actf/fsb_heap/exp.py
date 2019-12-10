from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process()
else:
	p = remote()

p.interactive()
