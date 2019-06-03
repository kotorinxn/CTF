#!/usr/bin/python2.7
# coding:utf-8
# 请勿修改整体模板，check 函数中内容需要根据题目进行完善
# eg: python check.py 192.168.8.101 8888
from sys import *
from pwn import *
import time

host = argv[1]
port = int(argv[2])
timeout = 30

# except return Correct/Error info, not return another info
context.log_level = 'critical'

def getIO():
    return remote(host, port, timeout=timeout)

def check1():
    try:
        p = getIO()
        info = p.recvuntil(">")
        if "Welcome to be dessert of kotori" not in info:
            raise Exception, "welcome msg broken"
        p.sendline('1')
        info = p.recvuntil("input your name:\n")
        p.sendline('kud')
        info = p.recvuntil("dessert:\n")
        if "malloc" in info:
            raise Exception, "malloc error"
        p.sendline("10")
        info = p.recvuntil("dessert:\n")
        p.sendline("wafu!cccc")
        info = p.recvuntil("chars:\n")
        p.sendline("wafuwafu")
        info = p.recvuntil(">")
        p.sendline("2")
        info = p.recvuntil("index:")
        p.sendline("0")
        info = p.recvuntil(">")
        if "kud" not in info or "wafu" not in info:
            raise Exception, "wrong storage"
        p.sendline("3")
        info = p.recvuntil("index:")
        p.sendline("0")
        info = p.recvuntil("new size:")
        p.sendline("26")
        info = p.recvuntil("dessert:")
        p.sendline('wafu! \xe5\x93\x87\xe5\x91\xbc\xef\xbc\x81w\xc4\x81 h\xc3\xb9')
        info = p.recvuntil(">")
        p.sendline("2")
        info = p.recvuntil("index:")
        p.sendline("0")
        info = p.recvuntil(">")
        if "kud" not in info or "\xe5\x93\x87\xe5\x91\xbc\xef\xbc\x81" not in info:
            raise Exception, "probably block non-ascii characters!"
        p.sendline("4")
        info = p.recvuntil("index:\n")
        p.sendline("0")
        info = p.recvuntil(">")
        p.sendline("1")
        info = p.recvuntil("input your name:\n")
        p.sendline('nagisa')
        info = p.recvuntil("dessert:\n")
        if "malloc" in info:
            raise Exception, "malloc error"
        p.sendline("20")
        info = p.recvuntil("dessert:\n")
        p.sendline("<?php phpinfo(); ?>")
        info = p.recvuntil("chars:\n")
        p.sendline("deadbeef")
        info = p.recvuntil(">")
        
        p.sendline("2")
        info = p.recvuntil("index:")
        p.sendline("0")
        info = p.recvuntil(">")
        if "nagisa" not in info or "phpinfo()" not in info:
            raise Exception, "wrong when deleting elem"
        p.close()

    except Exception as e:
        # add your check error description
        raise Exception, "Check1 error, "+str(e)
    return True

# simple all defend check
def check2():
    try:
        p = getIO()
        p.send('cat flag')
	    time.sleep(0.1)
        info = p.recv()
        if info != 'NO, Please continue! \n':
            raise Exception, "returnInfo no same"
        
    except Exception as e:
        # add your check error description
        raise Exception, "Check2 error, "+"something..."
    return True

# if want to add check, Please insert function like check3(p),check4(p) ...
def check3():
    try:
        p = getIO()
        info = p.recvuntil(">")
        if "Welcome to be dessert of kotori" not in info:
            raise Exception, "welcome msg broken"
	    p.sendline('1')
        info = p.recvuntil("input your name:\n")
        p.sendline('kud')
        info = p.recvuntil("sizeof dessert:\n")
        p.sendline("32")
        info = p.recvuntil("dessert:\n")
        p.sendline("wafu!cccc")
	    s1 = p.recvline()
        info = p.recvuntil("chars:\n")
        p.sendline("a")
        p.recvuntil(">")
	    p.sendline("4")
        info = p.recvuntil("index:\n")
        p.sendline("0")
	    p.sendline('1')
        info = p.recvuntil("input your name:\n")
        p.sendline('kud')
        info = p.recvuntil("sizeof dessert:\n")
        p.sendline("32")
        info = p.recvuntil("dessert:\n")
        p.sendline("wafu!cccc")
	    s2 = p.recvline()
	    if s1 != s2:
	        raise Exception, "free was patched!"
        info = p.recvuntil("chars:\n")
        p.sendline("a")
        p.close
        
    except Exception as e:
        # add your check error description
        raise Exception, "Check3 error, "+"something..."
    return True

def check4():
    return True

def checker():
    try:
        # add your check function name
        if check1() and check3():
            return (True, "IP: "+host+" OK")
    except Exception as e:
        return (False, "IP: "+host+" is down, "+str(e))

if __name__ == '__main__':
    print(checker())
