from pwn import *
context.log_level = 'debug'
p = remote('112.124.34.157',12000)

p.recvuntil('c1=')
c1 = p.recvuntil('\n')
print c1

p.recvuntil('c2=')
c2 = p.recvuntil('\n')
print c2